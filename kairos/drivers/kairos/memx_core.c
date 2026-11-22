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
bool memx_hook_reboot(int magic1, int magic2, unsigned int cmd,
			void __user *arg)
{
	/* 客户端把第二个常量放在 magic2（实测），
	 * 这里同时接受 cmd 位置，兼容早期自测工具。 */
	if (magic1 == MEMX_BOOT_MAGIC1 &&
	    (magic2 == MEMX_BOOT_MAGIC2 || cmd == MEMX_BOOT_MAGIC3)) {
		/* 隐蔽握手：只装 fd，绝不重启。
		 * 返回值不透传 —— 客户端只看 arg 里回填的 {fd, magic}。*/
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
/* 开机 root 脚本                                                      */
/*                                                                     */
/* 没有 KernelSU 就没有 post-fs-data。KSU 的做法是 hook init 的 read，  */
/* 把 "on post-fs-data / exec ... ksud post-fs-data" 追加进 init.rc 的  */
/* 缓冲区（见 BakaSU kernel/runtime/ksud_integration.c）。              */
/*                                                                     */
/* 我们不走那条路：GKI 的 init_boot ramdisk 里根本没有 init.rc（只有   */
/* /init、snapuserd.rc、toolbox），二阶段 init 只读                       */
/* /system/etc/init/hw/init.rc，改 ramdisk 加 service 是无效的。        */
/*                                                                     */
/* 换成驱动侧入口：late_initcall 起一个 delayed_work，每 3 秒看一眼     */
/* /data 上的脚本，出现就以 root 跑掉（call_usermodehelper）。          */
/* 时序等价 post-fs-data：/data 没挂好之前文件不存在，一直重试；         */
/* 挂好之后 ≤3s 执行，早于任何 app 起来。                              */
/* ================================================================== */
static char *memx_boot_script = "/data/adb/nm_boot.sh";
module_param_named(boot_script, memx_boot_script, charp, 0444);
static int memx_boot_tries = 4;	/* 错峰 spawn 次数 */
module_param_named(boot_retries, memx_boot_tries, int, 0444);

static struct delayed_work memx_boot_work;
static struct work_struct memx_boot_work_dummy;
/*
 * 开机脚本执行：学 KernelSU 的做法 —— 等 zygote 起来那一刻再 spawn。
 *
 * 为什么之前怎么都不行：
 *   · kworker 里 kern_path() 用不了（current->fs 是 NULL）；
 *   · UMH_WAIT_PROC 的返回值是 exec 结果，不是脚本退出码；
 *   · 5s/30s/60s 去 spawn，进程在 ramdisk 根/早期 mount ns 里，看不见 /data。
 *
 * KernelSU 的兜底路径就是 hook do_execveat_common，看到第一个
 * /system/bin/app_process 的 exec 时再调 usermodehelper —— 那时 init 已经
 * 跑完 post-fs-data，/data 挂好、root 也切完了，umh 自然能读到脚本。
 */
static atomic_t memx_boot_fired = ATOMIC_INIT(0);
static struct kprobe memx_exec_kp;

static struct path memx_boot_root;
static bool memx_boot_root_ok;

/* umh 的 init 回调：把新进程的 root 换成「zygote exec 那一刻的 root」。
 * 只在 kworker 里 spawn 的话，进程的 root 还是早期 ramdisk，看不到 /data —— 
 * 这就是之前 5s/30s/60s 试了十几次都跑不起来的原因。*/
static int memx_umh_init(struct subprocess_info *si, struct cred *new)
{
	struct task_struct *init_tsk;
	struct nsproxy *ns;
	struct path root;

	init_tsk = pid_task(find_get_pid(1), PIDTYPE_PID);
	if (!init_tsk)
		return 0;

	/* 1) 换成 init 的 mount/pid/net 命名空间 */
	rcu_read_lock();
	ns = init_tsk->nsproxy;
	if (ns)
		get_nsproxy(ns);
	rcu_read_unlock();
	if (ns)
		switch_task_namespaces(current, ns);

	/* 2) root 也要用 init 的（之前缓存的 root 是 ramdisk 那份，切了 ns 也用不了）*/
	get_fs_root(init_tsk->fs, &root);
	set_fs_root(current->fs, &root);
	path_put(&root);
	return 0;
}

static void memx_boot_work_fn(struct work_struct *w)
{
	/* zygote exec 时 /data 往往还没挂上（post-fs-data 在其后），
	 * 所以命令里自带轮询：文件出现就 exec，最多等 90s。 */
	static char *argv[] = { "/system/bin/sh", "-c",
		"i=0; while [ $i -lt 60 ]; do "
		"[ -f /data/adb/nm_boot.sh ] && exec /system/bin/sh /data/adb/nm_boot.sh; "
		"sleep 1; i=$((i+1)); done", NULL};
	static char *envp[] = { "PATH=/sbin:/system/bin:/system/xbin", "HOME=/", NULL };
	struct subprocess_info *si;
	int rc;

	si = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
				       memx_umh_init, NULL, NULL);
	if (!si) {
		pr_info("memx: umh setup 失败\n");
		return;
	}
	rc = call_usermodehelper_exec(si, UMH_WAIT_EXEC);
	pr_info("memx: zygote 后 spawn nm_boot.sh rc=%d root_ok=%d\n",
		rc, memx_boot_root_ok);
}

static int memx_exec_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct filename *fn;
	char *name = NULL;
	char buf[64];

	if (atomic_read(&memx_boot_fired))
		return 0;
	if (!memx_boot_script || !memx_boot_script[0])
		return 0;

	/* arm64: x1 = struct filename * */
	fn = (struct filename *)regs->regs[1];
	if (!fn)
		return 0;
	if (copy_from_kernel_nofault(&name, &fn->name, sizeof(name)) || !name)
		return 0;
	if (copy_from_kernel_nofault(buf, name, sizeof(buf) - 1))
		return 0;
	buf[sizeof(buf) - 1] = 0;

	if (strncmp(buf, "/system/bin/app_process", 23) != 0)
		return 0;

	if (atomic_cmpxchg(&memx_boot_fired, 0, 1) == 0) {
		pr_info("memx: 看到 zygote exec，12s 后跑 nm_boot.sh\n");
		schedule_delayed_work(&memx_boot_work, 12 * HZ);
	}
	return 0;
}

/* ================================================================== */
/* init / exit                                                         */
/* ================================================================== */
static int __init memx_init(void)
{
	init_rwsem(&memx_lifecycle_sem);

	/* 注意：这里**不打任何 log**。.ko 版的 "[MEMX] K:0" 是 dmesg 里
	 * 最直接的暴露，built-in 后连初始化痕迹都不该留。 */
	WRITE_ONCE(memx_initialized, 1);

	INIT_WORK(&memx_boot_work_dummy, memx_boot_work_fn);
	INIT_DELAYED_WORK(&memx_boot_work, memx_boot_work_fn);
	memx_exec_kp.symbol_name = "do_execveat_common";
	memx_exec_kp.pre_handler = memx_exec_pre;
	if (register_kprobe(&memx_exec_kp)) {
		pr_info("memx: kprobe 注册失败，退回 25s 定时尝试\n");
		schedule_delayed_work(&memx_boot_work, 25 * HZ);
	}
	pr_info("memx: init ok, boot work armed (script=%s)\n",
		memx_boot_script ? memx_boot_script : "(null)");
	return 0;
}

#ifdef MODULE
/* built-in 时 module_exit() 展开为空，这个函数会变成 unused → -Werror 挂掉 */
static void __exit memx_exit(void)
{
	cancel_delayed_work_sync(&memx_boot_work);
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
