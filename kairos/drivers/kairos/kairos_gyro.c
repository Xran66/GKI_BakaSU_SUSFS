// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_gyro.c — 陀螺仪包改写（从 gyro_sendto_handler @0x1f4b8 转写）
 *
 * ── 原理 ────────────────────────────────────────────────────
 * 游戏的传感器上报以 UDP sendto 发出，包体是定长记录数组：
 *   记录长度 0x68 = 104 字节
 *   记录内 +0x08 : u32 类型（只处理 4 和 16，由 type_mask 选择）
 *   记录内 +0x18 : float X
 *   记录内 +0x1C : float Y
 *
 * 驱动在 sendto 出口把 X/Y 做缩放/翻转/互换，再写回**用户态原缓冲区**。
 * 效果是压枪/锁头，且完全不碰游戏进程内存 —— 这是它绕过内存扫描的原因。
 *
 * ── 两个必须注意的内核限制 ───────────────────────────────────
 *  1. arm64 内核用 -mgeneral-regs-only 编译，**禁止任何浮点/SIMD 运算**。
 *     所以这里的缩放不能用 float，只能用 IEEE754 整数位运算实现
 *     （kairos_f32_scale：拆符号/阶码/尾数 → 整数乘 → 重新规格化）。
 *  2. 不能用 module_param：built-in 时会在
 *     /sys/module/kernel/parameters/ 下露出 gyro_enable 等五个参数，
 *     属于白送的指纹。改用 ioctl 配置，编进内核时参数表为空。
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/math64.h>

#include "kairos.h"

#define GYRO_REC_SIZE	0x68
#define GYRO_OFF_TYPE	0x08
#define GYRO_OFF_X	0x18
#define GYRO_OFF_Y	0x1C
#define GYRO_MAX_LEN	0x200000	/* 2MB，与原版一致 */

static int gyro_enable		= 1;
static int gyro_mode;			/* 0: 正常 1: X/Y互换并取反 2: 双取反 3: 只互换 */
static int gyro_scale_x		= 100;	/* 百分比 */
static int gyro_scale_y		= 100;
static int gyro_type_mask	= 0x3;	/* bit0: type 4, bit1: type 16 */

static unsigned int g_gyro_seq;

unsigned int kairos_gyro_stamp(void)
{
	return ++g_gyro_seq;
}

/* ================================================================== */
/* IEEE754 单精度整数缩放                                              */
/*                                                                     */
/* 内核里不能用浮点，所以直接动位域：                                   */
/*   bits = sign | exp<<23 | mant                                        */
/*   value = (1.mant) * 2^(exp-127)                                      */
/* 把尾数扩展成 24 位整数 sig，实际指数 e = exp-150（含尾数隐含位移），  */
/* 乘上百分比后重新规格化回 [2^23, 2^24)，再拼回去。                     */
/* 精度损失 < 1 ULP，对陀螺仪这种数据完全够用。                          */
/* ================================================================== */
static u32 kairos_f32_scale(u32 bits, int pct)
{
	u32 sign = bits & 0x80000000u;
	u32 exp  = (bits >> 23) & 0xFFu;
	u32 mant = bits & 0x7FFFFFu;
	s64 sig;
	int e;

	if (pct == 100 || !pct)
		return bits;
	if (exp == 0xFFu)		/* inf / NaN：原样放行 */
		return bits;
	if (exp == 0) {
		if (!mant)
			return bits;	/* 正负零 */
		sig = mant;		/* 次正规数 */
		e = -149;
	} else {
		sig = mant | 0x800000u;
		e = (int)exp - 150;
	}

	sig = div_s64(sig * (s64)pct, 100);
	if (sig <= 0)
		return sign;		/* 下溢成零，保留符号 */

	/* 规格化到 24 位有效位 */
	while (sig >= 0x1000000LL) {
		sig >>= 1;
		e++;
	}
	while (sig && sig < 0x800000LL) {
		sig <<= 1;
		e--;
	}
	if (!sig)
		return sign;

	e += 150;
	if (e >= 255)
		return sign | 0x7F800000u;	/* 溢出成 inf */
	if (e <= 0)
		return sign;			/* 下溢成 0（不细分次正规） */

	return sign | ((u32)e << 23) | ((u32)sig & 0x7FFFFFu);
}

/* 位级取负：等价于把 float 的符号位翻转（比 mode 里 ^0x80000000 更准确） */
static inline u32 kairos_f32_neg(u32 bits)
{
	return bits ^ 0x80000000u;
}

static inline bool kairos_type_match(u32 type)
{
	return (type == 4 && (gyro_type_mask & 1)) ||
	       (type == 16 && (gyro_type_mask & 2));
}

bool kairos_is_gyro_packet(const void *hdr, size_t len)
{
	const u8 *p = hdr;
	u32 type;

	if (!gyro_enable || len < GYRO_REC_SIZE || len % GYRO_REC_SIZE)
		return false;
	if (len > GYRO_MAX_LEN)
		return false;

	memcpy(&type, p + GYRO_OFF_TYPE, sizeof(type));
	return kairos_type_match(type);
}

/*
 * 就地改写一个包，返回改写的记录数（负数=失败）。
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

	kbuf = kvmalloc(len, GFP_KERNEL);	/* sendto 在进程上下文，可以睡眠 */
	if (!kbuf)
		return -ENOMEM;
	if (copy_from_user(kbuf, data, len)) {
		kvfree(kbuf);
		return -EFAULT;
	}

	nrec = len / GYRO_REC_SIZE;
	for (i = 0; i < nrec; i++) {
		u8 *rec = kbuf + i * GYRO_REC_SIZE;
		u32 type, bx, by;
		int vx, vy;

		memcpy(&type, rec + GYRO_OFF_TYPE, 4);
		if (!kairos_type_match(type))
			continue;

		memcpy(&bx, rec + GYRO_OFF_X, 4);
		memcpy(&by, rec + GYRO_OFF_Y, 4);
		vx = (int)bx;
		vy = (int)by;

		switch (gyro_mode) {
		case 1:				/* X/Y 互换并取反 */
			bx = kairos_f32_neg((u32)vy);
			by = kairos_f32_neg((u32)vx);
			break;
		case 2:				/* 双取反 */
			bx = kairos_f32_neg(bx);
			by = kairos_f32_neg(by);
			break;
		case 3:				/* 只互换 */
			bx = (u32)vy;
			by = (u32)vx;
			break;
		default:			/* 正常：只缩放 */
			break;
		}

		bx = kairos_f32_scale(bx, gyro_scale_x);
		by = kairos_f32_scale(by, gyro_scale_y);

		memcpy(rec + GYRO_OFF_X, &bx, 4);
		memcpy(rec + GYRO_OFF_Y, &by, 4);
		patched++;
	}

	if (patched && copy_to_user(data, kbuf, len)) {
		kvfree(kbuf);
		return -EFAULT;
	}
	kvfree(kbuf);
	return patched;
}

/* ================================================================== */
/* net/socket.c:__sys_sendto() 的注入入口                              */
/*                                                                     */
/* 放在 import_single_range() 之前，所以这里拿到的还是用户态指针。       */
/* 廉价预筛顺序：长度取模 → 内存最多 104 字节探针 → 类型判断            */
/* 普通 UDP 包（报文长度 % 104 != 0）第一关就出去了。                   */
/* ================================================================== */
void kairos_hook_sendto_buf(void __user *buf, size_t len)
{
	u8 probe[GYRO_REC_SIZE];

	if (!gyro_enable || !buf)
		return;
	if (len < GYRO_REC_SIZE || len % GYRO_REC_SIZE || len > GYRO_MAX_LEN)
		return;
	if (copy_from_user(probe, buf, sizeof(probe)))
		return;
	if (!kairos_is_gyro_packet(probe, len))
		return;

	kairos_gyro_patch(kairos_gyro_stamp(), buf, len);
}

/* ================================================================== */
/* 运行期配置（替代 .ko 版的 ioctl 写全局变量）                         */
/* ================================================================== */
void kairos_gyro_set(int enable, int mode, int sx, int sy, int mask)
{
	WRITE_ONCE(gyro_enable, enable);
	WRITE_ONCE(gyro_mode, mode);
	WRITE_ONCE(gyro_scale_x, sx);
	WRITE_ONCE(gyro_scale_y, sy);
	WRITE_ONCE(gyro_type_mask, mask);
}
