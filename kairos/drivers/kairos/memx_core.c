// SPDX-License-Identifier: GPL-2.0
/*
 * memx_core.c — 生命周期 + ghost fd 下发 + 源码级 hook 入口
 *
 * 相对 .ko 版删掉的东西（built-in 后都是多余的，且本身就是暴露面）：
 *   ✗ hide_module_work_fn / schedule_hide      —— 内核本体不在 module list 里
 *   ✗ list_del_rcu / kobject_del / module_mutex —— 同上
 *   ✗ memx_kallsyms_lookup_name() 自举        —— 内部符号可直接引用
 *   ✗ register_kprobe(__arm64_sys_reboot)       —— 改为 patch kernel/reboot.c
 *   ✗ register_kprobe(__arm64_sys_sendto)       —— 改为 patch net/socket.c
 *   ✗ "disabled N kprobe blacklist entries"     —— 不再动 kprobe 黑名单
 *   ✗ task_work_add 回传 fd 信息                —— 直接 copy_to_user 更简单
 * 保留的东西：
 *   ✓ anon_inode_getfile("[eventpoll]") 下发 fd —— 与现有客户端 ABI 完全兼容
 *   ✓ 全部 ioctl 命令号 / req 结构 / magic 校验
 */
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <linux/pid.h>
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
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>
#include <linux/umh.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/reboot.h>
#include <linux/syscalls.h>

#include "memx.h"

u8 memx_initialized;
struct rw_semaphore memx_lifecycle_sem;
struct memx_ctx *g_ctx;	/* 单个全局实例 */
/* install 只可能被调一次，用 mutex 而不是 spinlock：里面要 kzalloc(GFP_KERNEL) */
static DEFINE_MUTEX(memx_install_mutex);

bool memx_active(void)
{
	return READ_ONCE(memx_initialized) != 0;
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
static long memx_install_fd(void __user *out)
{
	struct memx_ctx *ctx, *old;
	struct file *f;
	int fd, magic;
	u32 reply[2];

	mutex_lock(&memx_install_mutex);

	/*
	 * 每次握手都装一个**新 fd**，绝不复用旧实例。
	 *
	 * 原来这里有一段"已有实例就把 fd/magic 再给它一次"的幂等逻辑，
	 * 在真机上会坏：客户端被 kill 时如果还残留子进程持有那个 anon fd，
	 * g_ctx 就一直绑在**上一个进程**的会话上，于是下一次握手把一个
	 * 属于别的进程的 fd 号返回给新进程 —— 新进程拿它 ioctl 必然失败，
	 * 表现就是"必须重启才能再用一次"。
	 *
	 * 旧 ctx 只解绑不释放：它归它自己的 file->private_data 管，
	 * 等那个 file 被关掉时由 memx_release() 负责 kfree。
	 */
	/*
	 * 只把全局指针摘掉，**不动旧 ctx 的 magic / authed / mm**。
	 *
	 * 客户端有多个工作进程共用同一个 fd（父进程握手、子进程继承）。
	 * 之前这里把旧 ctx 的 magic 清 0，等于让所有继承该 fd 的进程
	 * 在 dispatch 开头就被判 ENOTTY(-25) —— 表现就是"驱动连着但读不到数据"。
	 * 旧 ctx 的生命周期交给它自己的 file->private_data，等 file 关闭时
	 * 由 memx_release() 负责 kfree。
	 */
	old = xchg(&g_ctx, (struct memx_ctx *)NULL);
	(void)old;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		mutex_unlock(&memx_install_mutex);
		return fd;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		put_unused_fd(fd);
		mutex_unlock(&memx_install_mutex);
		return -ENOMEM;
	}

	f = anon_inode_getfile("[eventpoll]", &memx_fops, ctx,
			       O_RDWR | O_CLOEXEC);
	if (IS_ERR(f)) {
		kfree(ctx);
		put_unused_fd(fd);
		mutex_unlock(&memx_install_mutex);
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
	mutex_unlock(&memx_install_mutex);

	if (copy_to_user(out, reply, sizeof(reply)))
		return -EFAULT;
	return 0;
}

/* ================================================================== */
/* 只解绑 ctx / mm 引用，**不动 memx_initialized**                    */
/*                                                                     */
/* 为什么单独拆出来：Android 开机过程中会有进程调用                     */
/* reboot(标准 magic, 非法 cmd)，syscall 走到最后返回 EINVAL、机器并不  */
/* 会真的重启。原逻辑在这种"失败的 reboot"上就把驱动关掉了，导致本次   */
/* 开机内后续所有握手都失败（实测：TWRP 里正常，正常系统里握手 EINVAL）。*/
/* 真重启时内核会整个重来，清理本来就没意义。                          */
/* ================================================================== */
void memx_release_ctx(void)
{
	struct memx_ctx *ctx;

	/*
	 * 只摘全局指针，**不清 magic / authed / mm**。
	 *
	 * OP_EXIT 会调到这里。客户端是多进程共用同一个 fd（父进程握手、
	 * 工作进程继承），主进程关掉某个子窗口发一次 OP_EXIT，
	 * 如果把 magic 清 0，所有继承该 fd 的工作进程立刻被判 -ENOTTY(-25)，
	 * 表现就是"驱动连着但读取链路失败"。
	 *
	 * 会话状态交给它自己的 file：file 关闭时 memx_release() 负责 kfree。
	 */
	ctx = xchg(&g_ctx, (struct memx_ctx *)NULL);
	(void)ctx;
}

/* 彻底关停（只有 OP_EXIT 用）：解绑 + 置 initialized=0 */
void memx_shutdown_locked(void)
{
	if (!READ_ONCE(memx_initialized))
		return;
	WRITE_ONCE(memx_initialized, 0);
	memx_release_ctx();
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
 * 返回 true 表示已接管（调用方返回 -EPERM，既不重启也保持客户端 errno 一致）。
 */
bool memx_reboot_filter(int magic1, int magic2, unsigned int cmd,
			void __user *arg)
{
	/* 客户端把第二个常量放在 magic2（实测），
	 * 这里同时接受 cmd 位置，兼容早期自测工具。 */
	/* 官方加载器的「Kairos驱动是否加载」就是靠这个 reboot 魔术探测：
	 * 能装出 fd 并回填 {fd, magic} 就算已加载。之前让位官方驱动的改动
	 * 导致这里直接返回 false → 加载器报「Kairos驱动未加载」。恢复握手。 */
	if (magic1 == MEMX_BOOT_MAGIC1 &&
	    (magic2 == MEMX_BOOT_MAGIC2 || cmd == MEMX_BOOT_MAGIC3)) {
		(void)memx_install_fd(arg);
		return true;
	}

	/* 真正的重启流程：只解绑 fd/mm，**不要**把 initialized 清零 ——
	 * 否则任何一次失败的 reboot() 调用都会让驱动在本次开机内失效。 */
	if (magic1 == LINUX_REBOOT_MAGIC1 && magic2 == LINUX_REBOOT_MAGIC2) {
		down_write(&memx_lifecycle_sem);
		memx_release_ctx();
		up_write(&memx_lifecycle_sem);
	}
	return false;
}

/* ================================================================== */
/* init / exit                                                         */
/* ================================================================== */
/* 官方加载器（TIME_Cloud_Loader）会检查 /sys/module/KAIROS 是否存在，
 * 不存在就报「Kairos驱动未加载」。我们内建版自身是 memx_core，所以补一个
 * 同名 kobject 占位，让检查通过；这也和官方驱动的模块名保持一致。*/
static struct kobject *memx_kairos_kobj;

static int __init memx_init(void)
{
	init_rwsem(&memx_lifecycle_sem);
	WRITE_ONCE(memx_initialized, 1);

	/* /sys/module/KAIROS 占位 */
	memx_kairos_kobj = kobject_create_and_add("KAIROS", &module_kset->kobj);

	return 0;
}

#ifdef MODULE
/* built-in 时 module_exit() 展开为空，这个函数会变成 unused → -Werror 挂掉 */
static void __exit memx_exit(void)
{
	down_write(&memx_lifecycle_sem);
	memx_shutdown_locked();
	up_write(&memx_lifecycle_sem);
}
#endif

/*
 * 双模式：编进内核用 late_initcall（等 mm/swap/网络就绪），
 * 编成 .ko 用 module_init。同一份代码两种构建都能过。
 */
#ifdef MODULE
MODULE_LICENSE("GPL");
MODULE_AUTHOR("memx");
MODULE_DESCRIPTION("Memory range helper");
module_init(memx_init);
module_exit(memx_exit);
#else
late_initcall(memx_init);
#endif
