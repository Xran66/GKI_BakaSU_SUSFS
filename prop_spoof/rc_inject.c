// SPDX-License-Identifier: GPL-2.0
/*
 * rc_inject.c —— KernelSU 式 init.rc 注入（开机自启脚本的正路）
 *
 * 参考 KernelSU v0.7.5 kernel/ksud.c 的 vfs_read kprobe 手法：
 *   init（comm == "init"）读 /system/etc/init/atrace.rc 的第一次 read 时，
 *   把我们的 rc 文本 copy_to_user 到缓冲区头部，再用一个 proxy fops
 *   把每次 read 的返回长度加上 rc 长度 —— init 解析到的内容就变成了
 *   「我们的 rc 段 + 原文件」。
 *
 * 注入的 rc 段（不走 u:r:su:s0 —— init→su 的 transition 被 sepolicy 拒
 * （avc denied permissive=0，16:45 实测）；改为 exec root 后由脚本进程
 * execve SKRoot 的 su key 二进制，内核钩子在 execve(key) 时授 root 并
 * 处理 SELinux（与 app 的 su 路径完全同源）：
 *   on post-fs-data
 *       exec root -- /system/bin/sh -c "/data/AXRZTwzYMjRowUXf/su -c 'sh /data/adb/nm_boot.sh'"
 *   on property:sys.boot_completed=1
 *       exec u:r:su:s0 root -- /system/bin/sh /data/adb/nm_boot.sh
 *
 * u:r:su:s0 由内核里的 KSU/BakaSU sepolicy 引擎在开机早期打好。
 * 日志默认静默（防日志侧泄露），仅 PROP_SPOOF_TRACE 构建输出。
 */
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <asm/current.h>
#include <asm/ptrace.h>

/* arm64 C 调用约定取参（参照 KernelSU arch.h） */
#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_CCALL_PARM4(x) ((x)->regs[3])
#endif

/* 与 vps 同策略：默认静默 */
#ifdef PROP_SPOOF_TRACE
#define VPS_INFO(fmt, ...) pr_info("vps: " fmt, ##__VA_ARGS__)
#else
#define VPS_INFO(fmt, ...) do { } while (0)
#endif

static const char vpudev_rc_text[] =
	"\n"
	"on post-fs-data\n"
	"    exec root -- /system/bin/sh -c \"/data/AXRZTwzYMjRowUXf/su -c 'sh /data/adb/nm_boot.sh'\"\n"
	"\n"
	"on nonencrypted\n"
	"    exec root -- /system/bin/sh -c \"/data/AXRZTwzYMjRowUXf/su -c 'sh /data/adb/nm_boot.sh'\"\n"
	"\n"
	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec root -- /system/bin/sh -c \"/data/AXRZTwzYMjRowUXf/su -c 'sh /data/adb/nm_boot.sh'\"\n"
	"\n"
	"on property:sys.boot_completed=1\n"
	"    exec root -- /system/bin/sh -c \"/data/AXRZTwzYMjRowUXf/su -c 'sh /data/adb/nm_boot.sh'\"\n"
	"\n";

static ssize_t (*vpudev_orig_read)(struct file *, char __user *, size_t, loff_t *);
static ssize_t (*vpudev_orig_read_iter)(struct kiocb *, struct iov_iter *);
static struct file_operations vpudev_fops_shadow;
static ssize_t vpudev_rc_append;

static struct kprobe vpudev_read_probe_kp = {
	.symbol_name = "vfs_read",
	.pre_handler = NULL,
};

static void vpudev_read_probe_release(struct work_struct *work)
{
	unregister_kprobe(&vpudev_read_probe_kp);
	VPS_INFO("vfs_read kprobe 已拆除\n");
}
static DECLARE_WORK(vpudev_probe_release_work, vpudev_read_probe_release);

static ssize_t vpudev_read_shadow(struct file *file, char __user *buf, size_t count,
			  loff_t *pos)
{
	bool first_read = file->f_pos == 0;
	ssize_t ret = vpudev_orig_read(file, buf, count, pos);

	if (first_read)
		ret += vpudev_rc_append;
	return ret;
}

static ssize_t vpudev_read_iter_shadow(struct kiocb *iocb, struct iov_iter *to)
{
	bool first_read = iocb->ki_pos == 0;
	ssize_t ret = vpudev_orig_read_iter(iocb, to);

	if (first_read)
		ret += vpudev_rc_append;
	return ret;
}

static int vpudev_read_cb(struct file **file_ptr, char __user **buf_ptr,
			      size_t *count_ptr, loff_t **pos_ptr)
{
	struct file *file;
	char __user *buf;
	size_t count;
	char path[256];
	char *dpath;
	size_t rc_count = strlen(vpudev_rc_text);
	static bool rc_inserted;

	if (strcmp(current->comm, "init"))
		return 0; /* 只关心 init 进程 */

	file = *file_ptr;
	if (IS_ERR(file) || !file)
		return 0;
	if (!d_is_reg(file->f_path.dentry))
		return 0;

	if (strcmp(file->f_path.dentry->d_name.name, "atrace.rc"))
		return 0;

	dpath = d_path(&file->f_path, path, sizeof(path));
	if (IS_ERR(dpath))
		return 0;
	if (strcmp(dpath, "/system/etc/init/atrace.rc"))
		return 0;

	if (rc_inserted)
		return 0;
	rc_inserted = true;

	buf = *buf_ptr;
	count = *count_ptr;
	if (count < rc_count)
		return 0;

	if (copy_to_user(buf, vpudev_rc_text, rc_count)) {
		pr_err("vps: copy rc failed\n");
		return 0;
	}

	/* f_op 在只读内存，整体换成一个 proxy 副本 */
	memcpy(&vpudev_fops_shadow, file->f_op, sizeof(struct file_operations));
	vpudev_orig_read = file->f_op->read;
	if (vpudev_orig_read)
		vpudev_fops_shadow.read = vpudev_read_shadow;
	vpudev_orig_read_iter = file->f_op->read_iter;
	if (vpudev_orig_read_iter)
		vpudev_fops_shadow.read_iter = vpudev_read_iter_shadow;
	file->f_op = &vpudev_fops_shadow;
	vpudev_rc_append = rc_count;

	*buf_ptr = buf + rc_count;
	*count_ptr = count - rc_count;

	VPS_INFO("init.rc 注入完成（%s, rc=%zu 字节）\n", dpath, rc_count);

	/* 拆 kprobe（延迟到 workqueue，避免 kprobe 上下文里直接注销） */
	schedule_work(&vpudev_probe_release_work);

	return 0;
}

static int vpudev_read_probe(struct kprobe *p, struct pt_regs *regs)
{
	struct file **file_ptr = (struct file **)&PT_REGS_PARM1(regs);
	char __user **buf_ptr = (char **)&PT_REGS_PARM2(regs);
	size_t *count_ptr = (size_t *)&PT_REGS_PARM3(regs);
	loff_t **pos_ptr = (loff_t **)&PT_REGS_CCALL_PARM4(regs);

	return vpudev_read_cb(file_ptr, buf_ptr, count_ptr, pos_ptr);
}

static int __init vpudev_rc_attach(void)
{
	int ret;

	vpudev_read_probe_kp.pre_handler = vpudev_read_probe;
	ret = register_kprobe(&vpudev_read_probe_kp);
	if (ret)
		pr_err("vps: vfs_read kprobe 注册失败 %d\n", ret);

	return 0;
}
late_initcall(vpudev_rc_attach);
