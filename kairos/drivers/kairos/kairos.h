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
/* 客户端用 reboot() 做隐蔽握手拿 ghost fd 时使用的私有 magic
 * （原版 reboot_handler_pre @0x6284 里的字面量，不是任何标准 reboot 常量）*/
/*
 * 写入开关。
 *
 * 实际用途里只读不写（自瞄/透视都是读游戏内存），写入路径没有使用场景，
 * 关闭它可以：
 *   · 避免误写游戏内存（写穿 COW 会污染 fork 共享页 / page cache）
 *   · 少一条可被检测的攻击面
 * 代码全部保留在 kairos_mem.c 里，需要时把这个宏改成 1 即可恢复。
 */
#ifndef KAIROS_WRITE_ENABLE
#define KAIROS_WRITE_ENABLE	0
#endif

#define KAIROS_BOOT_MAGIC1	0x48931414
/*
 * 客户端的真实调用（用 kprobe 在 __arm64_sys_reboot 上实测抓到）：
 *     reboot(0x48931414, 0x51239123, 0, &out)
 * 即 magic1 = MAGIC1、**magic2** = 0x51239123、cmd = 0。
 *
 * 之前反编译 reboot_handler_pre 时把 `*((_DWORD *)v2 + 2)` 当成了偏移 16（cmd），
 * 实际 (DWORD*)+2 = **+8 字节 = magic2**，所以位置判错了。
 * KAIROS_BOOT_MAGIC3 保留为兼容别名。
 */
#define KAIROS_BOOT_MAGIC2	0x51239123
#define KAIROS_BOOT_MAGIC3	KAIROS_BOOT_MAGIC2
#define KAIROS_KEY_LEN		64
#define KAIROS_MAGIC_REPLY	1102

/* 用户态 ABI 与 .ko 版保持一致，这样现有客户端二进制不用改 */
struct kairos_req {
	__u32 op;
	__u32 pad;
	__u64 arg;
};

/*
 * 陀螺仪运行期参数（KOP_0x8B0）。
 * 原版是靠某条 ioctl 直接写全局变量；built-in 后不能用 module_param
 * （会在 /sys/module/kernel/parameters/ 下露出来），所以走这条 op。
 * scale_x/scale_y 是百分比：100 = 原值不改写。
 */
struct kairos_gyro_cfg {
	__s32	enable;
	__s32	mode;		/* 0 正常 / 1 XY互换取反 / 2 双取反 / 3 只互换 */
	__s32	scale_x;
	__s32	scale_y;
	__s32	type_mask;	/* bit0: type 4, bit1: type 16 */
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
	int			fd;		/* 下发出去的 fd，幂等重发时回给客户端 */
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

/* ---- lifecycle ---- */
void kairos_shutdown_locked(void);
void kairos_release_ctx(void);

/* ---- ioctl ---- */
long kairos_dispatch(struct file *file, u32 magic, u32 op, void __user *arg);

/* ---- 从被 patch 的内核源码里调用（见 patches/）---- */
/*
 * net/socket.c:__sys_sendto() 注入点直接调这个，参数就是原始的
 * (void __user *buff, size_t len)。必须在 import_single_range() 之前调用，
 * 因为我们要改的是用户缓冲本身，而不是已经 import 好的 iov_iter。
 * 内部先做廉价的长度/类型预筛，非陀螺仪包几乎零开销返回。
 */
void kairos_hook_sendto_buf(void __user *buf, size_t len);
bool kairos_hook_reboot(int magic1, int magic2, unsigned int cmd,
			void __user *arg);
void kairos_gyro_set(int enable, int mode, int sx, int sy, int mask);

/* ---- 供内核其它子系统查询是否已初始化 ----
 * 必须是真函数（不能 static inline）：被 patch 的 net/socket.c 和
 * kernel/reboot.c 会 extern 引用它，inline 版在那些 TU 里没有符号。 */
bool kairos_active(void);

#endif /* _KAIROS_H */
