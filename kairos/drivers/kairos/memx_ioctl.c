// SPDX-License-Identifier: GPL-2.0
/*
 * memx_ioctl.c — ioctl 入口与命令分发（built-in 版）
 *
 * ABI 与 .ko 版完全一致：
 *     struct memx_req { u32 op; u32 pad; u64 arg; };
 *     ioctl(fd, magic, &req);
 * 两层结构：memx_ioctl() 管生命周期锁，memx_dispatch() 管命令分发。
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/mm.h>

#include "memx.h"

/* ================================================================== */
/* 内存读写请求（0x8D0 / 0x8D2）                                       */
/*                                                                     */
/* 注意：这个结构是从 dispatch_request 的 copy_from_user 长度 + 寄存器  */
/* 用法反推出来的，**没有**和客户端二进制逐字段核对过。首次联调时先打印 */
/* 一次原始字节确认偏移，别直接信。                                     */
/* ================================================================== */
struct memx_mem_req {
	u32	pid;
	u32	pad;
	u64	va;
	u64	buf;
	u64	len;
	u32	mode;		/* bit0: 1=写 0=读, bit1: 1=安全路径(GUP) */
	u32	pad2;
};

/* ================================================================== */
/* 按文件名查模块基址（对应原版 dispatch 的 0x803）                     */
/*                                                                     */
/* 原版实现：grab_mm_by_pid → down_read(mmap_lock) → 遍历 VMA，        */
/*   比 vma->vm_file->f_path.dentry->d_name.name 与传入字符串，        */
/*   命中就返回 vma->vm_start；没命中返回 0。                          */
/* 客户端用它"等游戏模块出现"，拿不到就一直每秒轮询。                  */
/* ================================================================== */
static unsigned long memx_image_base(struct mm_struct *mm, const char *name)
{
	struct vm_area_struct *vma;
	unsigned long ret = 0;

	if (!name || !name[0])
		return 0;

	mmap_read_lock(mm);
	{
		VMA_ITERATOR(vmi, mm, 0);

		for_each_vma(vmi, vma) {
			const char *fn;

			if (!vma->vm_file)
				continue;
			fn = vma->vm_file->f_path.dentry->d_name.name;
			if (fn && !strcmp(fn, name)) {
				ret = vma->vm_start;
				break;
			}
		}
	}
	mmap_read_unlock(mm);

	return ret;
}

/* ================================================================== */
/* batch read/write (0x801/0x8D1 read, 0x802 write), 64KB chunks       */
/* ================================================================== */
static long memx_do_range(void __user *uarg, bool write)
{
	struct {
		__u32 pid;
		__u32 pad;
		__u64 va;
		__u64 buf;
		__u64 len;
	} r;
	struct mm_struct *mm;
	unsigned long off = 0;
	void *kbuf;
	long ret = 0;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;
	if (!r.len || r.len > 0xA00000 || r.va < 0x1000)
		return -EINVAL;

	mm = r.pid ? memx_task_mm_attach(r.pid) : get_task_mm(current);
	if (!mm)
		return -ESRCH;

	kbuf = kvzalloc(SZ_64K, GFP_KERNEL);
	if (!kbuf) {
		mmput(mm);
		return -ENOMEM;
	}

	while (off < r.len) {
		unsigned long n = min_t(unsigned long, SZ_64K, r.len - off);

		if (write) {
			if (copy_from_user(kbuf, (void __user *)(r.buf + off), n)) {
				ret = -EFAULT;
				break;
			}
			if (memx_write_to_mm(mm, r.va + off, kbuf, n, true) != n) {
				ret = -EINVAL;
				break;
			}
		} else {
			if (memx_read_to_kbuf(mm, r.va + off, kbuf, n) != n) {
				ret = -EINVAL;
				break;
			}
			if (copy_to_user((void __user *)(r.buf + off), kbuf, n)) {
				ret = -EFAULT;
				break;
			}
		}
		off += n;
	}

	kvfree(kbuf);
	mmput(mm);
	return ret;
}

/* ================================================================== */
/* 0x8D0 / 0x8D2：批量读多个区间                                        */
/*                                                                     */
/* 原版请求体（decomp_all.md 的 xc29a9955...）：                        */
/*   [0x0000] u32 pid                                                   */
/*   [0x0004] u32 count        1..256，0 直接成功返回                    */
/*   [0x0008] entry[count]     每项 16 字节 {u64 va; u32 len; u32 pad}   */
/*   [0x1008] out[0x8000]      各段数据依次写入（8 + 256*16 = 0x1008）   */
/* 累计长度超 0x8000 或某段读不全就停下，最终返回 0。                    */
/*                                                                     */
/* 之前按 {pid,pad,va,buf,len,mode} 解析，len 落在 entry 数组中间，      */
/* 永远是非法值 → 每次调用都 -EINVAL，这就是"驱动通但读不到数据"。       */
/* ================================================================== */
struct memx_batch_entry {
	__u64	va;
	__u32	len;
	__u32	pad;
};

#define MEMX_BATCH_OUT_OFF	0x1008
#define MEMX_BATCH_OUT_MAX	0x8000

static long memx_do_batch(void __user *uarg)
{
	struct {
		__u32 pid;
		__u32 count;
	} h;
	struct mm_struct *mm;
	void *kbuf;
	unsigned long acc = 0;
	__u32 i;
	long ret = 0;

	if (copy_from_user(&h, uarg, sizeof(h)))
		return -EFAULT;
	if (!h.count)
		return 0;
	if (h.count > 256)
		return -EINVAL;

	mm = h.pid ? memx_task_mm_attach(h.pid) : get_task_mm(current);
	if (!mm)
		return -ESRCH;

	kbuf = kvmalloc(SZ_64K, GFP_KERNEL);
	if (!kbuf) {
		mmput(mm);
		return -ENOMEM;
	}

	for (i = 0; i < h.count; i++) {
		struct memx_batch_entry e;
		unsigned long n, got;

		if (copy_from_user(&e, (char __user *)uarg + 8 + (size_t)i * sizeof(e),
				   sizeof(e))) {
			ret = -EFAULT;
			break;
		}
		n = e.len;
		if (!n)
			continue;
		if (acc + n > MEMX_BATCH_OUT_MAX)
			break;
		if (n > SZ_64K)
			break;

		if (e.va < 0x1000) {		/* 原版对低地址直接给零 */
			if (clear_user((char __user *)uarg + MEMX_BATCH_OUT_OFF + acc, n)) {
				ret = -EFAULT;
				break;
			}
			acc += n;
			continue;
		}

		got = memx_read_to_kbuf(mm, e.va, kbuf, n);
		if (got != n)
			break;
		if (copy_to_user((char __user *)uarg + MEMX_BATCH_OUT_OFF + acc,
				 kbuf, n)) {
			ret = -EFAULT;
			break;
		}
		acc += n;
	}

	kvfree(kbuf);
	mmput(mm);
	return ret;
}

static long __maybe_unused memx_do_mem(struct memx_ctx *ctx, void __user *uarg)
{
	struct memx_mem_req r;
	struct mm_struct *mm;
	void *kbuf;
	unsigned long done, n;
	bool write;
	int ret = 0;

	if (copy_from_user(&r, uarg, sizeof(r)))
		return -EFAULT;
	if (!r.len || r.len > SZ_32M)
		return -EINVAL;

	/*
	 * pid == 0 约定为"当前进程"（部分客户端这么用）。
	 * 直接丢给 find_get_pid(0) 会返回 -ESRCH，被客户端当成读取失败。
	 */
	if (r.pid == 0) {
		mm = get_task_mm(current);
	} else {
		mm = (ctx->mm && ctx->mm_pid == r.pid) ? ctx->mm
						       : memx_task_mm_attach(r.pid);
	}
	if (!mm)
		return -ESRCH;

	kbuf = kvmalloc(min_t(size_t, r.len, SZ_1M), GFP_KERNEL);
	if (!kbuf) {
		if (mm != ctx->mm)
			mmput(mm);
		return -ENOMEM;
	}

	write = r.mode & 1;
#if !MEMX_WRITE_ENABLE
	if (write) {			/* 写入已停用，代码保留 */
		ret = -EOPNOTSUPP;
		goto out;
	}
#endif
	n = min_t(unsigned long, r.len, SZ_1M);

	if (write) {
		if (copy_from_user(kbuf, (void __user *)r.buf, n)) {
			ret = -EFAULT;
			goto out;
		}
		done = memx_write_to_mm(mm, r.va, kbuf, n, !(r.mode & 2));
	} else {
		done = memx_read_to_kbuf(mm, r.va, kbuf, n);
		if (copy_to_user((void __user *)r.buf, kbuf, done))
			ret = -EFAULT;
	}

	if (!ret)
		ret = done;		/* 与 .ko 版一致：返回实际处理字节数 */
out:
	kvfree(kbuf);
	if (mm != ctx->mm)
		mmput(mm);
	return ret;
}

/* ================================================================== */
/* 分发                                                                */
/* ================================================================== */
long memx_dispatch(struct file *file, u32 magic, u32 op, void __user *uarg)
{
	struct memx_ctx *ctx = file->private_data;
	u8 buf[MEMX_MAX_REQ];
	u32 pid, v;
	long ret;

	if (!ctx || !ctx->magic || ctx->magic != magic)
		return -ENOTTY;
	if (op != KOP_AUTH && !ctx->authed)
		return -EACCES;

	memset(buf, 0, sizeof(buf));

	switch (op) {
	case KOP_AUTH:
		/* 原版固定读 64 字节；读 255 会越过客户端的小缓冲 */
		if (copy_from_user(buf, uarg, MEMX_KEY_LEN))
			return -EFAULT;
		if (memx_auth_check(buf))	/* 算法见 memx_auth.c / decomp_all.md */
			return -EACCES;
		ctx->authed = 1;
		return 0;

	case KOP_MAGIC:
		v = MEMX_MAGIC_REPLY;
		return copy_to_user(uarg, &v, 4) ? -EFAULT : 0;

	case KOP_KSGL_HIDE_PID:
	case KOP_KSGL_HIDE_PID2:
		if (copy_from_user(&pid, uarg, 4))
			return -EFAULT;
		/* built-in 版：kgsl debugfs 条目由 memx_gpudev.c 在创建时就不生成，
		 * 不需要事后删除。这里保留命令号仅为了 ABI 兼容，返回成功即可。 */
		return 0;

	case KOP_KSGL_HIDE_CUR:
		return 0;

	case KOP_MEM_A:
	case KOP_MEM_A2:
		return memx_do_batch(uarg);

	case KOP_EXIT:
		/*
		 * 只解绑本次会话，**不关停驱动**。
		 *
		 * 原来这里调 memx_shutdown_locked() 会把 memx_initialized 清 0，
		 * 结果是客户端一次 OP_EXIT 之后整个开机内都握手失败，
		 * 必须重启设备才能再用一次。
		 *
		 * 现在改成长驻：清掉认证状态和 mm 引用，让 g_ctx 回到 NULL，
		 * 下次握手会重新装一个新 fd。要真正停用只能重启（或卸载模块）。
		 */
		/*
		 * 只解绑全局指针，**不清 magic / authed / mm**。
		 *
		 * 客户端是多进程共用同一个 fd：主进程关掉某个子窗口就发一次
		 * OP_EXIT，如果这里把 magic 清 0，所有继承该 fd 的工作进程
		 * 会立刻被 dispatch 判 -ENOTTY(-25) —— 就是"驱动连着但读不到数据"。
		 */
		(void)ctx;
		memx_release_ctx();
		return 0;

	/* 以下命令 .ko 版存在但本次未复刻（触摸注入 / 抓包 / PAC 读写）。
	 * 保留命令号，返回 -EOPNOTSUPP，保证客户端不会误判成 fd 失效。 */
	/*
	 * 触摸注入（见 memx_touch.c）。
	 *   0x809 attach {screen_w, screen_h, orientation}
	 *   0x810 down   {slot, x, y}
	 *   0x811 move   {slot, x, y}
	 *   0x812 up     {slot}
	 *   0x814 / 0x817 detach
	 */
	case KOP_TOUCH_ATTACH:
	case KOP_TOUCH_1:
	case KOP_TOUCH_2:
	case KOP_TOUCH_3: {
		struct {
			__u32 a;
			__u32 b;
			__u32 c;
		} t;

		if (copy_from_user(&t, uarg, sizeof(t)))
			return -EFAULT;

		if (op == KOP_TOUCH_ATTACH)
			return memx_touch_attach((int)t.a, (int)t.b, (int)t.c);
		if (op == KOP_TOUCH_1)
			return memx_touch_down((int)t.a, (int)t.b, (int)t.c);
		if (op == KOP_TOUCH_2)
			return memx_touch_move((int)t.a, (int)t.b, (int)t.c);
		return memx_touch_up((int)t.a);
	}

	case KOP_TOUCH_DETACH:
	case KOP_TOUCH_DETACH2:
		return memx_touch_detach();

	case KOP_0x920:
	case KOP_0x921:
	case KOP_0x922:
		return -EOPNOTSUPP;


	case KOP_GET_TPIDR:
	case KOP_GET_TPIDR2:
	case KOP_GET_PACGA:
	case KOP_BIND_PACGA:
	case KOP_GET_FPSTATE:
	case KOP_GET_SIGSEGV:
		return -EOPNOTSUPP;
	/*
	 * 0x801 / 0x8D1: batch read    0x802: batch write
	 *
	 * 32-byte request:
	 *   [0x00] u32 pid   [0x04] u32 pad
	 *   [0x08] u64 va    [0x10] u64 buf   [0x18] u64 len
	 * (va >= 0x1000, len <= 0xA00000)  -- 64KB chunks, 0 on success / -EINVAL
	 *
	 * 之前这四个 case 被合并成"模块基址"逻辑，参数布局完全不同，
	 * 客户端用它取数据必然失败 —— UI 取不到数据的直接原因。
	 */
	case KOP_0x801:
	case KOP_0x8D1:
		return memx_do_range(uarg, false);

	case KOP_0x802:
#if MEMX_WRITE_ENABLE
		return memx_do_range(uarg, true);
#else
		/* 写入已停用（见 memx.h 的 MEMX_WRITE_ENABLE），代码保留 */
		return -EOPNOTSUPP;
#endif

	/*
	 * 0x8B0：枚举目标进程的所有线程 TID（**不是**陀螺仪配置！）
	 *
	 * 原版：copy_from_user(1032) → s[0]=pid，s[1]=计数，
	 *        遍历 task->signal->thread_head，s[2..] 存 task_pid_nr_ns(thread)，
	 *        最多 256 个，最后 copy_to_user(1032) 回写。
	 */
	case KOP_0x8B0: {
		struct {
			__u32 pid;
			__u32 count;
			__u32 tids[256];
		} *r;
		struct task_struct *task, *th;
		__u32 n = 0;

		r = kmalloc(sizeof(*r), GFP_KERNEL);
		if (!r)
			return -ENOMEM;
		if (copy_from_user(r, uarg, sizeof(*r))) {
			kfree(r);
			return -EFAULT;
		}
		r->count = 0;

		rcu_read_lock();
		task = find_task_by_vpid(r->pid);
		if (task) {
			for_each_thread(task, th) {
				if (n >= 256)
					break;
				r->tids[n++] = task_pid_nr_ns(th, NULL);
			}
		}
		rcu_read_unlock();

		r->count = n;
		if (copy_to_user(uarg, r, sizeof(*r))) {
			kfree(r);
			return -EFAULT;
		}
		kfree(r);
		return 0;
	}

	/*
	 * 0x911：原版在这里 register_kprobe(sendto) 并置 g_gyro_registered=1。
	 * 我们是源码级 hook，常驻生效，所以直接返回成功。
	 */
	case KOP_0x911:
		return 0;

	/*
	 * 0x910：陀螺仪参数配置（原版 g_gyro_registered 必须为 1 才放行）。
	 *
	 * 24 字节结构（原版字段顺序）：
	 *   [0x00] u32 enable
	 *   [0x04] u32 type_mask   0 时默认 3
	 *   [0x08] u32 scale_x
	 *   [0x0C] u32 scale_y
	 *   [0x10] u32 mode        0..3，越界归 0
	 *   [0x14] u32 consume_n
	 * 处理完把当前状态回写同样的 24 字节。
	 */
	case KOP_0x910: {
		struct {
			__u32 enable;
			__u32 type_mask;
			__u32 scale_x;
			__u32 scale_y;
			__u32 mode;
			__u32 consume_n;
		} c;

		if (copy_from_user(&c, uarg, sizeof(c)))
			return -EFAULT;
		if (!c.type_mask)
			c.type_mask = 3;
		if (c.mode >= 4)
			c.mode = 0;

		memx_gyro_set(c.enable ? 1 : 0, (int)c.mode,
				(int)c.scale_x, (int)c.scale_y, (int)c.type_mask);

		if (copy_to_user(uarg, &c, sizeof(c)))
			return -EFAULT;
		return 0;
	}

	/* 0x803: module base by file name (24-byte in/out) */
	case KOP_0x803: {
		struct {
			__u32 pid;
			__u32 pad;
			__u64 name;
			__u64 base;
		} r;
		char name[256];
		struct mm_struct *mm;

		if (copy_from_user(&r, uarg, sizeof(r)))
			return -EFAULT;
		memset(name, 0, sizeof(name));
		if (r.name && copy_from_user(name, (void __user *)r.name, sizeof(name) - 1))
			return -EFAULT;

		mm = r.pid ? memx_task_mm_attach(r.pid) : get_task_mm(current);
		if (!mm)
			return -ESRCH;

		r.base = (__u64)memx_image_base(mm, name);
		mmput(mm);

		if (copy_to_user(uarg, &r, sizeof(r)))
			return -EFAULT;
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

/* ================================================================== */
/* fd 入口与 fops                                                      */
/* ================================================================== */
static long memx_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct memx_req req;
	bool exclusive;
	long r;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
		return -EFAULT;

	switch (req.op) {
	case KOP_TOUCH_ATTACH:
	case KOP_EXIT:
	case KOP_TOUCH_DETACH:
	case KOP_TOUCH_DETACH2:
		exclusive = true;
		break;
	default:
		exclusive = false;
	}

	/* .ko 版对这四个 op 用 down_write，其余用 down_read；保持一致 */
	if (exclusive) {
		down_write(&memx_lifecycle_sem);
		r = memx_active()
			? memx_dispatch(file, cmd, req.op, (void __user *)req.arg)
			: -ENODEV;
		up_write(&memx_lifecycle_sem);
	} else {
		down_read(&memx_lifecycle_sem);
		r = memx_active()
			? memx_dispatch(file, cmd, req.op, (void __user *)req.arg)
			: -ENODEV;
		up_read(&memx_lifecycle_sem);
	}
	return r;
}

static int memx_release(struct inode *inode, struct file *file)
{
	struct memx_ctx *ctx = file->private_data;

	if (ctx) {
		if (ctx->mm)
			mmput(ctx->mm);
		if (READ_ONCE(g_ctx) == ctx)
			WRITE_ONCE(g_ctx, NULL);
		kfree(ctx);
	}
	return 0;
}

const struct file_operations memx_fops = {
#ifdef MODULE
	.owner		= THIS_MODULE,	/* built-in 时 THIS_MODULE 为 NULL，没必要写 */
#endif
	.unlocked_ioctl	= memx_ioctl,
	.release	= memx_release,
};
