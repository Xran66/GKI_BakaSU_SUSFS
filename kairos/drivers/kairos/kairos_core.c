// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_core.c — 生命周期 + ghost fd 下发 + 源码级 hook 入口
 *
 * 相对 .ko 版删掉的东西（built-in 后都是多余的，且本身就是暴露面）：
 *   ✗ hide_module_work_fn / schedule_hide      —— 内核本体不在 module list 里，无需隐藏
 *   ✗ list_del_rcu / kobject_del / module_mutex —— 同上
 *   ✗ kairos_kallsyms_lookup_name() 自举        —— 内核内部符号可直接引用
 *   ✗ register_kprobe(__arm64_sys_reboot)       —— 改为 patch kernel/reboot.c 直接调用
 *   ✗ register_kprobe(__arm64_sys_sendto)       —— 改为 patch net/socket.c 直接调用
 *   ✗ "disabled N kprobe blacklist entries"     —— 不再需要动 kprobe 黑名单
 *   ✗ task_work_add 自举                        —— 直接用 task_work_add()
 * 保留的东西：
 *   ✓ anon_inode_getfile("[eventpoll]") 下发 fd —— 与现有客户端 ABI 完全兼容
 *   ✓ 全部 ioctl 命令号 / req 结构 / magic 校验
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <net/sock.h>
#include <linux/syscalls.h>

#include "kairos.h"

u8 kairos_initialized;
struct rw_semaphore kairos_lifecycle_sem;
struct kairos_ctx *g_ctx;	/* 单个全局实例，比 .ko 版更省内存 */

/* ================================================================== */
/* ghost fd                                                            */
/*                                                                     */
/* 保留 "[eventpoll]" 名字：客户端的 find_fd_by_devt_in_proc 依赖这个   */
/* 形态在 /proc/self/fd 里认出它。改成 netlink 或隐藏 ioctl 会让现有     */
/* 客户端二进制失效 —— 除非同时改客户端，否则这里不动。                  */
/* ================================================================== */
struct kairos_install_work {
	struct callback_head	twork;
	void __user		*out;
	struct { u32 fd; u32 magic; } result;
};

static void kairos_install_tw(struct callback_head *t)
{
	struct kairos_install_work *w =
		container_of(t, struct kairos_install_work, twork);

	if (w->out)
		copy_to_user(w->out, &w->result, 8);
	kfree(w);
}

static long kairos_install_fd(void __user *out)
{
	struct kairos_install_work *w;
	struct kairos_ctx *ctx;
	struct file *f;
	int fd, magic;

	if (READ_ONCE(g_ctx))		/* 幂等：已有实例就直接复用 */
		return -EBUSY;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	f = anon_inode_getfile("[eventpoll]", &kairos_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(f)) {
		put_unused_fd(fd);
		return PTR_ERR(f);
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		fput(f);
		put_unused_fd(fd);
		return -ENOMEM;
	}
	do {
		magic = get_random_u32();
	} while (!magic);
	ctx->magic = magic;

	f->private_data = ctx;
	WRITE_ONCE(g_ctx, ctx);
	fd_install(fd, f);

	w = kmalloc(sizeof(*w), GFP_KERNEL);
	if (!w)
		return 0;
	w->result.fd = fd;
	w->result.magic = magic;
	w->out = out;
	init_task_work(&w->twork, kairos_install_tw);
	if (task_work_add(current, &w->twork, TWA_RESUME))
		kfree(w);

	return 0;
}

/* ================================================================== */
/* 关停（供 OP_EXIT 与 reboot hook 调用）                              */
/* ================================================================== */
void kairos_shutdown_locked(void)
{
	struct kairos_ctx *ctx;

	if (!READ_ONCE(kairos_initialized))
		return;
	WRITE_ONCE(kairos_initialized, 0);

	ctx = xchg(&g_ctx, NULL);
	if (ctx) {
		if (ctx->mm) {
			mmput(ctx->mm);	/* .ko 版用 mmdrop，这里用配对的 mmput */
			ctx->mm = NULL;
		}
		kfree(ctx);
	}
}

/* ================================================================== */
/* 源码级 hook 入口（由 patches/ 里的 diff 插入调用点）                  */
/* ================================================================== */
#ifdef CONFIG_KAIROS_GYRO_HOOK
/*
 * 在 net/socket.c:__sys_sendto() 入口调用。
 * 原版是靠 kprobe pre_handler 拿到 regs 再改用户缓冲区；built-in 后
 * 我们有完整的 C 上下文，直接改 __user 缓冲即可，且不污染 kprobe 表。
 *
 * 返回：可能被修改后的 iov 长度（不改就原样返回）
 */
size_t kairos_hook_sendto(struct socket *sock, struct user_msghdr *umsg,
			  size_t len)
{
	struct kairos_gyro_hdr hdr;
	void __user *data;
	unsigned int seq;

	if (!kairos_active())
		return len;

	if (copy_from_user(&hdr, umsg, sizeof(hdr)))
		return len;

	/* 只处理陀螺仪 UDP 特征包，其余原样放行 */
	if (!kairos_is_gyro_packet(&hdr, len))
		return len;

	data = (void __user *)(unsigned long)hdr.iov_base;
	seq = kairos_gyro_stamp();
	if (kairos_gyro_patch(seq, data, len) < 0)
		kairos_log("gyro: patch failed\n");
	return len;
}
#endif

void kairos_hook_reboot(int magic1, int magic2)
{
	if (!kairos_active())
		return;
	/* 原版 reboot_handler_pre 主要做关停清理，避免关机时 hook 残留 */
	if (magic1 == LINUX_REBOOT_MAGIC1 && magic2 == LINUX_REBOOT_MAGIC2) {
		down_write(&kairos_lifecycle_sem);
		kairos_shutdown_locked();
		up_write(&kairos_lifecycle_sem);
	}
}

/* ================================================================== */
/* init / exit                                                         */
/* ================================================================== */
static int __init kairos_init(void)
{
	init_rwsem(&kairos_lifecycle_sem);

	/* 注意：这里**不打任何 log**。.ko 版的 "[KAIROS] K:0" 是 dmesg 里
	 * 最直接的暴露，built-in 后连初始化的痕迹都不该留。 */
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
