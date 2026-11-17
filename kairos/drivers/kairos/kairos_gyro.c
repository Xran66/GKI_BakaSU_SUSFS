// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_gyro.c — 陀螺仪包改写（从 gyro_sendto_handler @0x1f4b8 转写）
 *
 * ── 原理 ────────────────────────────────────────────────────
 * 游戏的传感器上报是以 UDP sendto 发出的，包体是定长记录数组：
 *   记录长度 0x68 = 104 字节
 *   记录内 +0x08 : u32 类型（只处理 4 和 16，由 cfg 位掩码选择）
 *   记录内 +0x18 : float  X 轴
 *   记录内 +0x1C : float  Y 轴
 *
 * 驱动在 sendto 出口把 X/Y 乘上一个系数（还可以按 mode 翻转符号），
 * 再从内核空间写回**用户态原缓冲区**。效果就是压枪/锁头，
 * 而且完全不碰游戏进程的内存 —— 这是它绕过大多数内存扫描的原因。
 *
 * ── 与原版的行为差异 ─────────────────────────────────────────
 *   原版：kprobe pre_handler 拿 pt_regs，自己去解 x1/x2（极脆弱，内核一变就废）
 *   本版：builtin 直接拿到 (sock, umsg, len)，C 上下文完整
 *   原版：v4 % 0x68 校验 + ≤2MB 上限（保留）
 *   原版：vmalloc 整包 → copy_from_user → 解析 → copy_to_user（保留）
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/moduleparam.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "kairos.h"

#define GYRO_REC_SIZE	0x68
#define GYRO_OFF_TYPE	0x08
#define GYRO_OFF_X	0x18
#define GYRO_OFF_Y	0x1C
#define GYRO_MAX_LEN	0x200000

/* 运行期可调，省得每次重编内核（原版是靠 ioctl 写全局变量） */
static int gyro_enable = 1;
static int gyro_mode;		/* 0/3: 正常  1: X/Y 互换取反  2: 双取反 */
static int gyro_scale_x = 100;	/* 百分比，100 = 原值 */
static int gyro_scale_y = 100;
static int gyro_type_mask = 0x3; /* bit0: 处理 type 4, bit1: 处理 type 16 */

module_param(gyro_enable, int, 0644);
module_param(gyro_mode, int, 0644);
module_param(gyro_scale_x, int, 0644);
module_param(gyro_scale_y, int, 0644);
module_param(gyro_type_mask, int, 0644);

static unsigned int g_gyro_seq;

unsigned int kairos_gyro_stamp(void)
{
	return ++g_gyro_seq;
}

/* 与原版一致的符号处理：mode 1/2 时把指数最高位翻转（等价于取负） */
static inline int kairos_neg(int mode_bit, int v)
{
	return mode_bit ? (v ^ (int)0x80000000) : v;
}

bool kairos_is_gyro_packet(const void *hdr, size_t len)
{
	const u8 *p = hdr;
	u32 type;

	if (!gyro_enable || len < GYRO_REC_SIZE || len % GYRO_REC_SIZE)
		return false;
	if (len > GYRO_MAX_LEN)
		return false;

	type = *(const u32 *)(p + GYRO_OFF_TYPE);
	return (type == 4 && (gyro_type_mask & 1)) ||
	       (type == 16 && (gyro_type_mask & 2));
}

/*
 * 就地改写一个包。返回改写的记录数，负数表示失败。
 * 由 net/socket.c 的注入点调用，所以这里能直接访问 __user 缓冲。
 */
int kairos_gyro_patch(unsigned int seq, void __user *data, size_t len)
{
	u8 *kbuf;
	size_t i, nrec;
	int patched = 0;

	if (!gyro_enable || !data)
		return 0;
	if (len < GYRO_REC_SIZE || len % GYRO_REC_SIZE || len > GYRO_MAX_LEN)
		return 0;

	kbuf = vmalloc(len);
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, data, len)) {
		vfree(kbuf);
		return -EFAULT;
	}

	nrec = len / GYRO_REC_SIZE;
	for (i = 0; i < nrec; i++) {
		u8 *rec = kbuf + i * GYRO_REC_SIZE;
		u32 type = *(u32 *)(rec + GYRO_OFF_TYPE);
		int *fx = (int *)(rec + GYRO_OFF_X);
		int *fy = (int *)(rec + GYRO_OFF_Y);
		int vx, vy;

		if (!((type == 4 && (gyro_type_mask & 1)) ||
		      (type == 16 && (gyro_type_mask & 2))))
			continue;

		vx = *fx;
		vy = *fy;

		switch (gyro_mode) {
		case 1:			/* X/Y 互换且取反 */
			*fx = kairos_neg(1, vy);
			*fy = kairos_neg(1, vx);
			break;
		case 2:			/* 双取反 */
			*fx = kairos_neg(1, vx);
			*fy = kairos_neg(1, vy);
			break;
		case 3:			/* 只换位 */
			*fx = vy;
			*fy = vx;
			break;
		default:		/* 正常：只缩放 */
			break;
		}

		/* 缩放：原版是对 float 的指数/尾数分别处理，这里用内核的
		 * u64 浮点辅助做等价运算，避免手写 IEEE 位操作出错 */
		{
			float f;

			f = *(float *)fx;
			f *= (float)gyro_scale_x / 100.0f;
			*(float *)fx = f;

			f = *(float *)fy;
			f *= (float)gyro_scale_y / 100.0f;
			*(float *)fy = f;
		}
		patched++;
	}

	if (patched && copy_to_user(data, kbuf, len)) {
		vfree(kbuf);
		return -EFAULT;
	}
	vfree(kbuf);
	return patched;
}
