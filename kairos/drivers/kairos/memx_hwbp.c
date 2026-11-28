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
static u64 bp_rn(struct pt_regs *regs, u32 rn)
{
	return rn == 31 ? regs->sp : regs->regs[rn];
}

static void bp_set_rn(struct pt_regs *regs, u32 rn, u64 v)
{
	if (rn == 31)
		regs->sp = v;
	else
		regs->regs[rn] = v;
}

static void bp_load(struct pt_regs *regs, u32 rt, u64 addr, int width)
{
	u64 v = 0;

	if (rt == 31)          /* xzr：读出来丢弃 */
		return;

	if (width == 8) {
		if (copy_from_user_nofault(&v, (void __user *)addr, 8))
			return;
		regs->regs[rt] = v;
	} else {
		u32 v32 = 0;
		if (copy_from_user_nofault(&v32, (void __user *)addr, 4))
			return;
		regs->regs[rt] = v32;
	}
}

static u64 bp_val(struct pt_regs *regs, u32 rt)
{
	return rt == 31 ? 0 : regs->regs[rt];
}

static s64 bp_imm9(u32 insn)
{
	s64 v = (s64)((insn >> 12) & 0x1FF);
	return (v & 0x100) ? v - 0x200 : v;
}

static s64 bp_imm12(u32 insn)
{
	return (s64)((insn >> 10) & 0xFFF);
}

static s64 bp_imm7(u32 insn, int shift)
{
	s64 v = (s64)((insn >> 15) & 0x7F);
	if (v & 0x40)
		v -= 0x80;
	return v << shift;
}

/*
 * 补执行被跳过的访存/栈调整指令（覆盖 GKI 常见的 -O2 序言与收尾）：
 *   sub  sp, sp, #imm12
 *   ldr/str  xt, [xn, #imm12*size]        (unsigned offset)
 *   ldr/str  xt, [xn, #imm9]!             (pre-index)
 *   ldr/str  xt, [xn], #imm9              (post-index)
 *   ldp/stp  xt, xt2, [xn, #imm7*size]    (offset / pre / post)
 */
static void memx_bp_emulate(struct pt_regs *regs, u32 insn)
{
	u32 rt, rt2, rn;
	u64 base;
	s64 off;

	if (!insn)
		return;

	/* sub sp, sp, #imm */
	if ((insn & 0xFFC003FF) == 0xD10003FF) {
		u32 imm12 = (insn >> 10) & 0xFFF;
		u32 sh = (insn >> 22) & 1;
		regs->sp -= sh ? ((u64)imm12 << 12) : imm12;
		return;
	}

	/* ---- 单寄存器 ldr/str ---- */
	/* unsigned offset: size|111|0|01|01 */
	if ((insn & 0xFFC00000) == 0xF9400000 ||   /* ldr x */
	    (insn & 0xFFC00000) == 0xB9400000 ||   /* ldr w */
	    (insn & 0xFFC00000) == 0xF9000000 ||   /* str x */
	    (insn & 0xFFC00000) == 0xB9000000) {   /* str w */
		int w = ((insn & 0xFFC00000) == 0xF9400000 ||
			 (insn & 0xFFC00000) == 0xF9000000) ? 8 : 4;
		int is_load = ((insn & 0xFFC00000) == 0xF9400000 ||
			       (insn & 0xFFC00000) == 0xB9400000);
		rt = insn & 0x1F;
		rn = (insn >> 5) & 0x1F;
		base = bp_rn(regs, rn);
		off = bp_imm12(insn) * w;
		if (is_load)
			bp_load(regs, rt, base + off, w);
		else
			bp_store(base + off, bp_val(regs, rt), w);
		return;
	}

	/* pre-index: size|111|0|00|11 */
	if ((insn & 0xFFE00C00) == 0xF8400C00 ||
	    (insn & 0xFFE00C00) == 0xB8400C00 ||
	    (insn & 0xFFE00C00) == 0xF8000C00 ||
	    (insn & 0xFFE00C00) == 0xB8000C00) {
		int is64 = ((insn & 0xFFE00C00) == 0xF8400C00 ||
			    (insn & 0xFFE00C00) == 0xF8000C00);
		int is_load = ((insn & 0xFFE00C00) == 0xF8400C00 ||
			       (insn & 0xFFE00C00) == 0xB8400C00);
		int w = is64 ? 8 : 4;
		rt = insn & 0x1F;
		rn = (insn >> 5) & 0x1F;
		base = bp_rn(regs, rn) + bp_imm9(insn);
		if (is_load)
			bp_load(regs, rt, base, w);
		else
			bp_store(base, bp_val(regs, rt), w);
		bp_set_rn(regs, rn, base);
		return;
	}

	/* post-index: size|111|0|00|01 */
	if ((insn & 0xFFE00C00) == 0xF8400400 ||
	    (insn & 0xFFE00C00) == 0xB8400400 ||
	    (insn & 0xFFE00C00) == 0xF8000400 ||
	    (insn & 0xFFE00C00) == 0xB8000400) {
		int is64 = ((insn & 0xFFE00C00) == 0xF8400400 ||
			    (insn & 0xFFE00C00) == 0xF8000400);
		int is_load = ((insn & 0xFFE00C00) == 0xF8400400 ||
			       (insn & 0xFFE00C00) == 0xB8400400);
		int w = is64 ? 8 : 4;
		rt = insn & 0x1F;
		rn = (insn >> 5) & 0x1F;
		base = bp_rn(regs, rn);
		if (is_load)
			bp_load(regs, rt, base, w);
		else
			bp_store(base, bp_val(regs, rt), w);
		bp_set_rn(regs, rn, base + bp_imm9(insn));
		return;
	}

	/* ---- 双寄存器 ldp/stp ---- */
	/* offset: 10|101|0|010|L|0 */
	if ((insn & 0xFFC00000) == 0xA9400000 ||   /* ldp x, offset */
	    (insn & 0xFFC00000) == 0x29400000 ||   /* ldp w, offset */
	    (insn & 0xFFC00000) == 0xA9000000 ||   /* stp x, offset */
	    (insn & 0xFFC00000) == 0x29000000) {   /* stp w, offset */
		int is64 = ((insn & 0xFFC00000) == 0xA9400000 ||
			    (insn & 0xFFC00000) == 0xA9000000);
		int is_load = ((insn & 0xFFC00000) == 0xA9400000 ||
			       (insn & 0xFFC00000) == 0x29400000);
		int w = is64 ? 8 : 4;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		rn  = (insn >> 5) & 0x1F;
		base = bp_rn(regs, rn);
		off = bp_imm7(insn, is64 ? 3 : 2);
		if (is_load) {
			bp_load(regs, rt, base + off, w);
			bp_load(regs, rt2, base + off + w, w);
		} else {
			bp_store(base + off, bp_val(regs, rt), w);
			bp_store(base + off + w, bp_val(regs, rt2), w);
		}
		return;
	}

	/* pre-index */
	if ((insn & 0xFFC00000) == 0xA9C00000 ||
	    (insn & 0xFFC00000) == 0x29C00000 ||
	    (insn & 0xFFC00000) == 0xA9800000 ||
	    (insn & 0xFFC00000) == 0x29800000) {
		int is64 = ((insn & 0xFFC00000) == 0xA9C00000 ||
			    (insn & 0xFFC00000) == 0xA9800000);
		int is_load = ((insn & 0xFFC00000) == 0xA9C00000 ||
			       (insn & 0xFFC00000) == 0x29C00000);
		int w = is64 ? 8 : 4;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		rn  = (insn >> 5) & 0x1F;
		off = bp_imm7(insn, is64 ? 3 : 2);
		base = bp_rn(regs, rn) + off;
		if (is_load) {
			bp_load(regs, rt, base, w);
			bp_load(regs, rt2, base + w, w);
		} else {
			bp_store(base, bp_val(regs, rt), w);
			bp_store(base + w, bp_val(regs, rt2), w);
		}
		bp_set_rn(regs, rn, base);
		return;
	}

	/* post-index */
	if ((insn & 0xFFC00000) == 0xA8C00000 ||
	    (insn & 0xFFC00000) == 0x28C00000 ||
	    (insn & 0xFFC00000) == 0xA8800000 ||
	    (insn & 0xFFC00000) == 0x28800000) {
		int is64 = ((insn & 0xFFC00000) == 0xA8C00000 ||
			    (insn & 0xFFC00000) == 0xA8800000);
		int is_load = ((insn & 0xFFC00000) == 0xA8C00000 ||
			       (insn & 0xFFC00000) == 0x28C00000);
		int w = is64 ? 8 : 4;
		rt  = insn & 0x1F;
		rt2 = (insn >> 10) & 0x1F;
		rn  = (insn >> 5) & 0x1F;
		base = bp_rn(regs, rn);
		if (is_load) {
			bp_load(regs, rt, base, w);
			bp_load(regs, rt2, base + w, w);
		} else {
			bp_store(base, bp_val(regs, rt), w);
			bp_store(base + w, bp_val(regs, rt2), w);
		}
		bp_set_rn(regs, rn, base + bp_imm7(insn, is64 ? 3 : 2));
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

	/* 先补执行被跳过的指令，再记录寄存器（记录值即"执行完该指令"的状态） */
	memx_bp_emulate(regs, insn);
	regs->pc += 4;

	spin_lock_irqsave(&g_bp_lock, flags);
	if (g_bp && current->tgid == g_bp->tgid) {
		int idx = g_bp->ring_head & (MEMX_BP_RING - 1);
		g_bp->ring[idx].pc = regs->pc - 4;
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
