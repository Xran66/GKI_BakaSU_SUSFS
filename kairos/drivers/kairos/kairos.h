/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kairos.h — 内置版公共头
 *
 * 与 .ko 版的差异（built-in 后能删掉的）：
 *   1. 不再需要 struct 偏移常量（mm->pgd / task->mm 直接用成员）
 *   2. 不再需要 kallsyms 自举（内核内部符号直接调用）
 *   3. 不再需要 THIS_MODULE / MODULE_* 宏 / hide_module_work_fn
 *   4. 不再需要 anon_inode "[eventpoll]" 伪装 —— 见 ioctl 注释
 */
#ifndef _KAIROS_H
#define _KAIROS_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

/* 生产构建下所有日志编译为空；审计要求：不留 dmesg 痕迹 */
#ifdef KAIROS_VERBOSE
#define kairos_log(fmt, ...)	pr_info("kairos: " fmt, ##__VA_ARGS__)
#else
#define kairos_log(fmt, ...)	do { } while (0)
#endif
#define kairos_err(fmt, ...)	pr_err_ratelimited("kairos: " fmt, ##__VA_ARGS__)

#define KAIROS_MAX_REQ		0xFF
#define KAIROS_KEY_LEN		64
#define KAIROS_MAGIC_REPLY	1102

/* 用户态 ABI 与 .ko 版保持一致，这样现有客户端二进制不用改 */
struct kairos_req {
	__u32 op;
	__u32 pad;
	__u64 arg;
};

enum kairos_op {
	KOP_AUTH		= 0x800,
	KOP_0x801		= 0x801,
	KOP_0x8D1		= 0x8D1,
	KOP_0x802		= 0x802,
	KOP_0x803		= 0x803,
	KOP_KSGL_HIDE_PID	= 0x804,
	KOP_KSGL_HIDE_CUR	= 0x807,
	KOP_TOUCH_ATTACH	= 0x809,
	KOP_TOUCH_1		= 0x810,
	KOP_TOUCH_2		= 0x811,
	KOP_TOUCH_3		= 0x812,
	KOP_EXIT		= 0x813,
	KOP_TOUCH_DETACH	= 0x814,
	KOP_MAGIC		= 0x815,
	KOP_TOUCH_DETACH2	= 0x817,
	KOP_KSGL_HIDE_PID2	= 0x820,
	KOP_GET_TPIDR		= 0x850,
	KOP_GET_TPIDR2		= 0x851,
	KOP_GET_PACGA		= 0x852,
	KOP_BIND_PACGA		= 0x853,
	KOP_GET_FPSTATE		= 0x855,
	KOP_GET_SIGSEGV		= 0x856,
	KOP_0x8B0		= 0x8B0,
	KOP_MEM_A		= 0x8D0,
	KOP_MEM_A2		= 0x8D2,
	KOP_0x910		= 0x910,
	KOP_0x911		= 0x911,
	KOP_0x920		= 0x920,
	KOP_0x921		= 0x921,
	KOP_0x922		= 0x922,
};

struct kairos_ctx {
	u8			authed;
	u32			magic;
	struct mm_struct	*mm;
	u32			mm_pid;
};

extern struct rw_semaphore kairos_lifecycle_sem;
extern u8 kairos_initialized;
extern struct kairos_ctx *g_ctx;
extern const struct file_operations kairos_fops;

int  kairos_auth_check(const u8 *blob);
int  kairos_expected_key(char *out, size_t outsz);
void kairos_base64(char *out, const u8 *in, int len);
bool kairos_is_gyro_packet(const void *hdr, size_t len);
int  kairos_gyro_patch(unsigned int seq, void __user *data, size_t len);
unsigned int kairos_gyro_stamp(void);

/* ---- mem ---- */
struct mm_struct *kairos_grab_mm_by_pid(pid_t pid);
unsigned long kairos_read_to_kbuf(struct mm_struct *mm, unsigned long va,
				  void *kbuf, unsigned long len);
unsigned long kairos_write_to_mm(struct mm_struct *mm, unsigned long va,
				 const void *kbuf, unsigned long len, bool safe);

/* ---- ioctl ---- */
long kairos_dispatch(struct file *file, u32 magic, u32 op, void __user *arg);

/* ---- 从被 patch 的内核源码里调用（见 patches/）---- */
int  kairos_hook_sendto(struct pt_regs *regs, void __user *msg, int len);
void kairos_hook_reboot(int magic1, int magic2);

/* ---- 供内核其它子系统查询是否已初始化 ---- */
static inline bool kairos_active(void)
{
	return READ_ONCE(kairos_initialized);
}

#endif /* _KAIROS_H */
