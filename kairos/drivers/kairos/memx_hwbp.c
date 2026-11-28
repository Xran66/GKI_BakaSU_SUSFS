// SPDX-License-Identifier: GPL-2.0
/*
 * memx_hwbp.c —— memx 硬件执行断点（A 路：抓 ACE 上报前明文）
 *
 * ABI:
 *   op 0x920 -> { u32 pid; u32 pad; u64 addr; }   在 pid 的**全部线程**上装 X 断点
 *   op 0x921 -> { u32 idx; u32 pad; u64 out; }    取第 idx 条命中（struct memx_bp_hit）
 *   op 0x922 -> NULL                              全部卸载
 *   op 0x923 -> { u32 pid; u32 pad; }             重新扫线程（补齐新起的线程）
 *
 * 要点：
 *  1) perf 的用户断点是 per-task（per-thread）的，进程里每个线程都要各装一个，
 *     否则只会在主线程命中（实测 ACE 的加密/上报跑在工作线程上）。
 *  2) arm64 命中后 CPU 停在同一条指令，直接返回会无限重入 → handler 里把 pc 前移 4，
 *     并**真正补执行**被跳过的那条指令（stp/str 序言必须写回用户栈，否则返回地址被踩）。
 *  3) handler 处于 hardirq 上下文，用户内存访问一律用 *_nofault 版本。
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <asm/ptrace.h>

#include "memx.h"

#define MEMX_BP_RING     64
#define MEMX_BP_MAX_INST 512

struct memx_bp_hit {
	__u64 pc;
	__u64 x[4];      /* x0..x3 */
	__u64 sp;
	__u32 pid;
	__u32 skipped;   /* 被跳过指令的原始 opcode（0 表示读取失败） */
};

struct memx_bp_inst {
	struct task_struct *task;
	struct perf_event *bp;
};

struct memx_bp {
	u32 tgid;
	u64 addr;
	int ninst;
	struct memx_bp_inst inst[MEMX_BP_MAX_INST];
	u32 ring_head;
	struct memx_bp_hit ring[MEMX_BP_RING];
};

static struct memx_bp *g_bp;
static DEFINE_SPINLOCK(g_bp_lock);

static void bp_store(u64 addr, u64 val, int width)
{
	if (width == 8) {
		u64 v = val;
		copy_to_user_nofault((void __user *)addr, &v, 8);
	} else {
		u32 v = (u32)val;
		copy_to_user_nofault((void __user *)addr, &v, 4);
	}
}

/*
 * 补执行被跳过的序言指令：
 *   sub  sp, sp, #imm
 *   stp  xN, xM, [sp, #-imm]!    (pre-index, 64/32 位)
 *   stp  xN, xM, [sp, #imm]      (signed offset)
 *   str  xN, [sp, #-imm]!        (pre-index, 64/32 位)
 */
static void memx_bp_emulate(struct pt_regs *regs, u32 insn)
{
	u32 rt, rt2;

	if (!insn)
		return;

	/* sub sp, sp, #imm */
	if ((insn & 0xFFC003FF) == 0xD10003FF) {
		u32 imm12 = (insn >> 10) & 0xFFF;
		u32 sh = (insn >> 22) & 1;
		regs->sp -= sh ? ((u64)imm12 << 12) : imm12;
		return;
	}

	/* stp 64-bit pre-index */
	if ((insn & 0xFFC00000) == 0xA9800000) {
		s64 off = (s64)((insn >> 15) & 0x7F);
		if (off & 0x40)
			off -= 0x80;
		off *= 8;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		regs->sp += off;
		bp_store(regs->sp, regs->regs[rt], 8);
		bp_store(regs->sp + 8, regs->regs[rt2], 8);
		return;
	}

	/* stp 32-bit pre-index */
	if ((insn & 0xFFC00000) == 0x29800000) {
		s64 off = (s64)((insn >> 15) & 0x7F);
		if (off & 0x40)
			off -= 0x80;
		off *= 4;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		regs->sp += off;
		bp_store(regs->sp, regs->regs[rt] & 0xFFFFFFFFull, 4);
		bp_store(regs->sp + 4, regs->regs[rt2] & 0xFFFFFFFFull, 4);
		return;
	}

	/* stp signed offset（不改 sp） */
	if ((insn & 0xFFC00000) == 0xA9000000) {
		s64 off = (s64)((insn >> 15) & 0x7F);
		if (off & 0x40)
			off -= 0x80;
		off *= 8;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		bp_store(regs->sp + off, regs->regs[rt], 8);
		bp_store(regs->sp + off + 8, regs->regs[rt2], 8);
		return;
	}

	/* str 64-bit pre-index */
	if ((insn & 0xFFE00C00) == 0xF8000C00) {
		s64 off = (s64)((insn >> 12) & 0x1FF);
		if (off & 0x100)
			off -= 0x200;
		rt = insn & 0x1F;
		regs->sp += off;
		bp_store(regs->sp, regs->regs[rt], 8);
		return;
	}

	/* str 32-bit pre-index */
	if ((insn & 0xFFE00C00) == 0xB8000C00) {
		s64 off = (s64)((insn >> 12) & 0x1FF);
		if (off & 0x100)
			off -= 0x200;
		rt = insn & 0x1F;
		regs->sp += off;
		bp_store(regs->sp, regs->regs[rt] & 0xFFFFFFFFull, 4);
		return;
	}

	/* 其它指令不模拟：仅在断点安放在安全位置时可接受 */
}

static void memx_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
			    struct pt_regs *regs)
{
	unsigned long flags;
	u32 insn = 0;

	if (copy_from_user_nofault(&insn, (void __user *)regs->pc, sizeof(insn)))
		insn = 0;

	spin_lock_irqsave(&g_bp_lock, flags);
	if (g_bp && current->tgid == g_bp->tgid) {
		int idx = g_bp->ring_head & (MEMX_BP_RING - 1);
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
	regs->pc += 4;
}

/*
 * 给 pid 的所有线程装断点；返回本次新装数量。
 * 分两阶段：先在 RCU 下把线程指针取出来（get_task_struct 保活），
 * 再在非 RCU 上下文注册 perf 事件（注册会分配内存，不能持 rcu_read_lock）。
 */
static int bp_attach_threads(struct memx_bp *nb, struct task_struct *leader)
{
	struct perf_event_attr attr;
	struct task_struct *t;
	struct task_struct *tmp[MEMX_BP_MAX_INST];
	int ntmp = 0, i, added = 0;

	rcu_read_lock();
	for_each_thread(leader, t) {
		bool dup = false;

		for (i = 0; i < nb->ninst; i++) {
			if (nb->inst[i].task == t) { dup = true; break; }
		}
		for (i = 0; i < ntmp; i++) {
			if (tmp[i] == t) { dup = true; break; }
		}
		if (dup)
			continue;
		if (nb->ninst + ntmp >= MEMX_BP_MAX_INST)
			break;
		get_task_struct(t);
		tmp[ntmp++] = t;
	}
	rcu_read_unlock();

	hw_breakpoint_init(&attr);
	attr.bp_addr = nb->addr;
	attr.bp_len = HW_BREAKPOINT_LEN_4;
	attr.bp_type = HW_BREAKPOINT_X;

	for (i = 0; i < ntmp; i++) {
		struct perf_event *ev;

		ev = register_user_hw_breakpoint(&attr, memx_bp_handler, NULL, tmp[i]);
		if (IS_ERR(ev)) {
			put_task_struct(tmp[i]);
			continue;
		}
		nb->inst[nb->ninst].task = tmp[i];
		nb->inst[nb->ninst].bp = ev;
		nb->ninst++;
		added++;
	}
	return added;
}

long memx_bp_set(void __user *uarg)
{
	struct { u32 pid; u32 pad; u64 addr; } r;
	struct task_struct *task;
	struct memx_bp *nb;
	int added;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;
	if (!r.pid || (r.addr & 3))
		return -EINVAL;

	if (g_bp)
		return -EBUSY;

	task = find_get_task_by_vpid(r.pid);
	if (!task)
		return -ESRCH;

	nb = kzalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb) {
		put_task_struct(task);
		return -ENOMEM;
	}
	nb->tgid = r.pid;
	nb->addr = r.addr;

	added = bp_attach_threads(nb, task);
	put_task_struct(task);

	if (added <= 0) {
		kfree(nb);
		return added < 0 ? added : -ESRCH;
	}

	spin_lock(&g_bp_lock);
	g_bp = nb;
	spin_unlock(&g_bp_lock);

	pr_info("memx: bp on %#llx tgid=%u threads=%d\n",
		(unsigned long long)nb->addr, nb->tgid, nb->ninst);
	return 0;
}

long memx_bp_refresh(void __user *uarg)
{
	struct { u32 pid; u32 pad; } r;
	struct task_struct *leader;
	int added;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;

	spin_lock(&g_bp_lock);
	if (!g_bp || g_bp->tgid != r.pid) {
		spin_unlock(&g_bp_lock);
		return -ENODATA;
	}
	spin_unlock(&g_bp_lock);

	leader = find_get_task_by_vpid(r.pid);
	if (!leader)
		return -ESRCH;
	added = bp_attach_threads(g_bp, leader);
	put_task_struct(leader);
	return added;
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

u32 memx_bp_count(void)
{
	u32 n;
	unsigned long flags;

	spin_lock_irqsave(&g_bp_lock, flags);
	n = g_bp ? g_bp->ring_head : 0;
	spin_unlock_irqrestore(&g_bp_lock, flags);
	return n;
}

long memx_bp_clear(void)
{
	struct memx_bp *old;
	int i;

	spin_lock(&g_bp_lock);
	old = g_bp;
	g_bp = NULL;
	spin_unlock(&g_bp_lock);

	if (!old)
		return -ENODATA;

	for (i = 0; i < old->ninst; i++) {
		if (old->inst[i].bp)
			unregister_hw_breakpoint(old->inst[i].bp);
		if (old->inst[i].task)
			put_task_struct(old->inst[i].task);
	}
	kfree(old);
	return 0;
}
