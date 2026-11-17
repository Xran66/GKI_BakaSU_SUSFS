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

	mm = (ctx->mm && ctx->mm_pid == r.pid) ? ctx->mm
					       : kairos_grab_mm_by_pid(r.pid);
	if (!mm)
		return -ESRCH;

	kbuf = kvmalloc(min_t(size_t, r.len, SZ_1M), GFP_KERNEL);
	if (!kbuf) {
		if (mm != ctx->mm)
			mmput(mm);
		return -ENOMEM;
	}

	write = r.mode & 1;
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
		ctx->authed = 0;
		ctx->magic = 0;
		if (ctx->mm) {
			mmput(ctx->mm);
			ctx->mm = NULL;
			ctx->mm_pid = 0;
		}
		kairos_shutdown_locked();
		return 0;

	/* 以下命令 .ko 版存在但本次未复刻（触摸注入 / 抓包 / PAC 读写）。
	 * 保留命令号，返回 -EOPNOTSUPP，保证客户端不会误判成 fd 失效。 */
	case KOP_TOUCH_ATTACH:
	case KOP_TOUCH_1:
	case KOP_TOUCH_2:
	case KOP_TOUCH_3:
	case KOP_TOUCH_DETACH:
	case KOP_TOUCH_DETACH2:
	case KOP_0x910:
	case KOP_0x911:
	case KOP_0x920:
	case KOP_0x921:
	case KOP_0x922:
		return -EOPNOTSUPP;

#ifdef CONFIG_KAIROS_GYRO_HOOK
	case KOP_0x8B0: {		/* 陀螺仪参数配置 */
		struct kairos_gyro_cfg cfg;

		if (copy_from_user(&cfg, uarg, sizeof(cfg)))
			return -EFAULT;
		if (cfg.scale_x < 0 || cfg.scale_x > 1000 ||
		    cfg.scale_y < 0 || cfg.scale_y > 1000)
			return -EINVAL;
		kairos_gyro_set(cfg.enable, cfg.mode,
				cfg.scale_x, cfg.scale_y, cfg.type_mask);
		return 0;
	}
#else
	case KOP_0x8B0:
		return -EOPNOTSUPP;
#endif

	case KOP_GET_TPIDR:
	case KOP_GET_TPIDR2:
	case KOP_GET_PACGA:
	case KOP_BIND_PACGA:
	case KOP_GET_FPSTATE:
	case KOP_GET_SIGSEGV:
		return -EOPNOTSUPP;

	/* 0x801/0x802/0x803 在原版里是"设置目标进程"类命令（写 ctx->mm_pid），
	 * 具体字段布局还没从 dispatch_request 里逐条核对，这里只做参数探测，
	 * 不落任何状态 —— 避免用错的布局把 mm 引用搞坏。 */
	case KOP_0x801:
	case KOP_0x8D1:
	case KOP_0x802:
	case KOP_0x803:
		if (copy_from_user(buf, uarg, 0x20))
			return -EFAULT;
		return 0;

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
