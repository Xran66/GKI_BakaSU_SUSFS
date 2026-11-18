// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_ioctl.c — ioctl 入口与命令分发（built-in 版）
 *
 * ABI 与 .ko 版完全一致：
 *     struct kairos_req { u32 op; u32 pad; u64 arg; };
 *     ioctl(fd, magic, &req);
 * 两层结构：kairos_ioctl() 管生命周期锁，kairos_dispatch() 管命令分发。
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

#include "kairos.h"

/* ================================================================== */
/* 内存读写请求（0x8D0 / 0x8D2）                                       */
/*                                                                     */
/* 注意：这个结构是从 dispatch_request 的 copy_from_user 长度 + 寄存器  */
/* 用法反推出来的，**没有**和客户端二进制逐字段核对过。首次联调时先打印 */
/* 一次原始字节确认偏移，别直接信。                                     */
/* ================================================================== */
struct kairos_mem_req {
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
static unsigned long kairos_find_module_base(struct mm_struct *mm, const char *name)
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
static long kairos_do_range(void __user *uarg, bool write)
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

	mm = r.pid ? kairos_grab_mm_by_pid(r.pid) : get_task_mm(current);
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
			if (kairos_write_to_mm(mm, r.va + off, kbuf, n, true) != n) {
				ret = -EINVAL;
				break;
			}
		} else {
			if (kairos_read_to_kbuf(mm, r.va + off, kbuf, n) != n) {
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

static long kairos_do_mem(struct kairos_ctx *ctx, void __user *uarg)
{
	struct kairos_mem_req r;
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
						       : kairos_grab_mm_by_pid(r.pid);
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
#if !KAIROS_WRITE_ENABLE
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
		done = kairos_write_to_mm(mm, r.va, kbuf, n, !(r.mode & 2));
	} else {
		done = kairos_read_to_kbuf(mm, r.va, kbuf, n);
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
long kairos_dispatch(struct file *file, u32 magic, u32 op, void __user *uarg)
{
	struct kairos_ctx *ctx = file->private_data;
	u8 buf[KAIROS_MAX_REQ];
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
		if (copy_from_user(buf, uarg, KAIROS_KEY_LEN))
			return -EFAULT;
		if (kairos_auth_check(buf))	/* 算法见 kairos_auth.c / decomp_all.md */
			return -EACCES;
		ctx->authed = 1;
		return 0;

	case KOP_MAGIC:
		v = KAIROS_MAGIC_REPLY;
		return copy_to_user(uarg, &v, 4) ? -EFAULT : 0;

	case KOP_KSGL_HIDE_PID:
	case KOP_KSGL_HIDE_PID2:
		if (copy_from_user(&pid, uarg, 4))
			return -EFAULT;
		/* built-in 版：kgsl debugfs 条目由 kairos_kgsl.c 在创建时就不生成，
		 * 不需要事后删除。这里保留命令号仅为了 ABI 兼容，返回成功即可。 */
		return 0;

	case KOP_KSGL_HIDE_CUR:
		return 0;

	case KOP_MEM_A:
	case KOP_MEM_A2:
		return kairos_do_mem(ctx, uarg);

	case KOP_EXIT:
		/*
		 * 只解绑本次会话，**不关停驱动**。
		 *
		 * 原来这里调 kairos_shutdown_locked() 会把 kairos_initialized 清 0，
		 * 结果是客户端一次 OP_EXIT 之后整个开机内都握手失败，
		 * 必须重启设备才能再用一次。
		 *
		 * 现在改成长驻：清掉认证状态和 mm 引用，让 g_ctx 回到 NULL，
		 * 下次握手会重新装一个新 fd。要真正停用只能重启（或卸载模块）。
		 */
		ctx->authed = 0;
		ctx->magic = 0;
		if (ctx->mm) {
			mmput(ctx->mm);
			ctx->mm = NULL;
			ctx->mm_pid = 0;
		}
		kairos_release_ctx();
		return 0;

	/* 以下命令 .ko 版存在但本次未复刻（触摸注入 / 抓包 / PAC 读写）。
	 * 保留命令号，返回 -EOPNOTSUPP，保证客户端不会误判成 fd 失效。 */
	case KOP_TOUCH_ATTACH:
	case KOP_TOUCH_1:
	case KOP_TOUCH_2:
	case KOP_TOUCH_3:
	case KOP_TOUCH_DETACH:
	case KOP_TOUCH_DETACH2:
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
		return kairos_do_range(uarg, false);

	case KOP_0x802:
#if KAIROS_WRITE_ENABLE
		return kairos_do_range(uarg, true);
#else
		/* 写入已停用（见 kairos.h 的 KAIROS_WRITE_ENABLE），代码保留 */
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

		kairos_gyro_set(c.enable ? 1 : 0, (int)c.mode,
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

		mm = r.pid ? kairos_grab_mm_by_pid(r.pid) : get_task_mm(current);
		if (!mm)
			return -ESRCH;

		r.base = (__u64)kairos_find_module_base(mm, name);
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
static long kairos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct kairos_req req;
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
		down_write(&kairos_lifecycle_sem);
		r = kairos_active()
			? kairos_dispatch(file, cmd, req.op, (void __user *)req.arg)
			: -ENODEV;
		up_write(&kairos_lifecycle_sem);
	} else {
		down_read(&kairos_lifecycle_sem);
		r = kairos_active()
			? kairos_dispatch(file, cmd, req.op, (void __user *)req.arg)
			: -ENODEV;
		up_read(&kairos_lifecycle_sem);
	}
	return r;
}

static int kairos_release(struct inode *inode, struct file *file)
{
	struct kairos_ctx *ctx = file->private_data;

	if (ctx) {
		if (ctx->mm)
			mmput(ctx->mm);
		if (READ_ONCE(g_ctx) == ctx)
			WRITE_ONCE(g_ctx, NULL);
		kfree(ctx);
	}
	return 0;
}

const struct file_operations kairos_fops = {
#ifdef MODULE
	.owner		= THIS_MODULE,	/* built-in 时 THIS_MODULE 为 NULL，没必要写 */
#endif
	.unlocked_ioctl	= kairos_ioctl,
	.release	= kairos_release,
};
