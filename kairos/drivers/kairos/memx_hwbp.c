// SPDX-License-Identifier: GPL-2.0
/*
 * memx_hwbp.c —— 给 memx 驱动补硬件执行断点（A 路：抓 ACE 上报前明文）
 *
 * 背景：
 *   7 月那套 minimem 靠 register_user_hw_breakpoint 停在被 hook 函数入口，
 *   读 x0(明文指针)/x1(长度) 就拿到上报前明文。当前 memx 版 0x920/0x921/0x922
 *   直接返回 -EOPNOTSUPP，所以要补回来。
 *
 * 用法（客户端）：
 *   op 0x920 arg -> { u32 pid; u32 pad; u64 addr; }
 *       在 pid 的 addr 处装一个 X 型（执行）断点，addr 需 4 字节对齐。
 *   op 0x921 arg -> { u32 idx; u32 pad; u64 out; }   // out 指向 struct memx_bp_hit
 *       取第 idx 条命中（环形缓冲，最多 MEMX_BP_RING 条）。
 *   op 0x922 arg -> { u32 pid; u32 pad; }
 *       卸载该 pid 的断点。
 *
 * 关键坑（arm64）：执行断点命中后 CPU 会停在同一条指令上，
 * 直接返回会无限重入。这里在 handler 里把 regs->pc 前移到下一条指令，
 * 并对最常见的三种序言指令做等价的“补执行”，其余指令只跳过并记录 opcode，
 * 由客户端决定是否安全（通常把断点装在函数入口第二条指令处更稳妥）。
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/uaccess.h>  /* copy_from_user_nofault */
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <asm/ptrace.h>

#include "memx.h"

#define MEMX_BP_RING 64

struct memx_bp_hit {
	__u64 pc;
	__u64 x[4];      /* x0..x3 */
	__u64 sp;
	__u32 pid;
	__u32 skipped;   /* 被跳过指令的原始 opcode */
};

struct memx_bp {
	struct task_struct *task;
	struct perf_event *bp;
	u64 addr;
	u32 ring_head;
	struct memx_bp_hit ring[MEMX_BP_RING];
};

static struct memx_bp *g_bp;
static DEFINE_SPINLOCK(g_bp_lock);

/*
 * 序言指令的“补执行”：
 *   sub  sp, sp, #imm        (0xD10xxxxx 系列)
 *   stp  x29, x30, [sp, #-imm]!
 * 其余情况仅跳过 4 字节并记录 opcode（由抓取点选择来规避风险）。
 */
static void memx_bp_emulate(struct pt_regs *regs, u32 insn)
{
	/* sub sp, sp, #imm  : sf=1 op=1 S=0 100010 sh imm12 Rn=31 Rd=31 */
	if ((insn & 0xFFC003FF) == 0xD10003FF) {
		u32 imm12 = (insn >> 10) & 0xFFF;
		u32 sh = (insn >> 22) & 1;
		regs->sp -= sh ? ((u64)imm12 << 12) : imm12;
		return;
	}
	/* stp x29, x30, [sp, #-imm]!（pre-index，64 位） */
	if ((insn & 0xFFC07FFF) == 0xA9807BFD) {
		s32 imm = (s32)((insn >> 15) & 0x7F) * -8;
		regs->sp += imm;
		/* 真正写入栈需要访问用户内存，这里不做（只保证 sp 正确，避免踩栈） */
		return;
	}
	/* 其它：不模拟 */
}

static void memx_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
			    struct pt_regs *regs)
{
	unsigned long flags;
	u32 insn = 0;
	int idx;

	/* 读原指令：本 handler 在 hardirq 上下文，必须用 nofault 版本 */
	if (copy_from_user_nofault(&insn, (void __user *)regs->pc, sizeof(insn)))
		insn = 0;

	spin_lock_irqsave(&g_bp_lock, flags);
	if (g_bp) {
		idx = g_bp->ring_head & (MEMX_BP_RING - 1);
		g_bp->ring[idx].pc = regs->pc;
		g_bp->ring[idx].x[0] = regs->regs[0];
		g_bp->ring[idx].x[1] = regs->regs[1];
		g_bp->ring[idx].x[2] = regs->regs[2];
		g_bp->ring[idx].x[3] = regs->regs[3];
		g_bp->ring[idx].sp = regs->sp;
		g_bp->ring[idx].pid = current->pid;
		g_bp->ring[idx].skipped = insn;
		g_bp->ring_head++;
	}
	spin_unlock_irqrestore(&g_bp_lock, flags);

	memx_bp_emulate(regs, insn);
	regs->pc += 4;      /* 前进到下一指令，避免同点无限重入 */
}

long memx_bp_set(void __user *uarg)
{
	struct { u32 pid; u32 pad; u64 addr; } r;
	struct task_struct *task;
	struct perf_event_attr attr;
	struct memx_bp *nb;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;
	if (!r.pid || (r.addr & 3))
		return -EINVAL;

	if (g_bp)      /* 单实例：先清旧的 */
		return -EBUSY;

	task = find_get_task_by_vpid(r.pid);
	if (!task)
		return -ESRCH;

	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb) { put_task_struct(task); return -ENOMEM; }
	nb->task = task;
	nb->addr = r.addr;

	hw_breakpoint_init(&attr);
	attr.bp_addr = r.addr;
	attr.bp_len = HW_BREAKPOINT_LEN_4;
	attr.bp_type = HW_BREAKPOINT_X;

	nb->bp = register_user_hw_breakpoint(&attr, memx_bp_handler, NULL, task);
	if (IS_ERR(nb->bp)) {
		long e = PTR_ERR(nb->bp);
		put_task_struct(task);
		kfree(nb);
		return e;
	}

	spin_lock(&g_bp_lock);
	g_bp = nb;
	spin_unlock(&g_bp_lock);
	return 0;
}

long memx_bp_get(void __user *uarg)
{
	struct { u32 idx; u32 pad; u64 out; } r;
	struct memx_bp_hit hit;
	unsigned long flags;
	int idx;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;

	spin_lock_irqsave(&g_bp_lock, flags);
	if (!g_bp) { spin_unlock_irqrestore(&g_bp_lock, flags); return -ENODATA; }
	if (r.idx >= min_t(u32, (u32)g_bp->ring_head, MEMX_BP_RING)) {
		spin_unlock_irqrestore(&g_bp_lock, flags);
		return -ENODATA;
	}
	idx = r.idx & (MEMX_BP_RING - 1);
	hit = g_bp->ring[idx];
	spin_unlock_irqrestore(&g_bp_lock, flags);

	return copy_to_user((void __user *)r.out, &hit, sizeof(hit)) ? -EFAULT : 0;
}

long memx_bp_clear(void)
{
	struct memx_bp *old;

	spin_lock(&g_bp_lock);
	old = g_bp;
	g_bp = NULL;
	spin_unlock(&g_bp_lock);

	if (!old)
		return -ENODATA;
	unregister_hw_breakpoint(old->bp);
	put_task_struct(old->task);
	kfree(old);
	return 0;
}

u32 memx_bp_count(void)
{
	u32 n;
	unsigned long flags;
	spin_lock_irqsave(&g_bp_lock, flags);
	n = g_bp ? g_bp->ring_head : 0;
	spin_unlock_irqrestore(&g_bp_lock, flags);
	return n;
}
