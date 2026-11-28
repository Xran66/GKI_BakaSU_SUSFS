// SPDX-License-Identifier: GPL-2.0
/*
 * memx_gyro.c — 陀螺仪包改写（从 gyro_sendto_handler @0x1f4b8 转写）
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
 *     （memx_f32_add：拆符号/阶码/尾数 → 对齐 → 相加 → 重新规格化）。
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

#include "memx.h"

#define GYRO_REC_SIZE	0x68
#define GYRO_OFF_TYPE	0x08
#define GYRO_OFF_X	0x18
#define GYRO_OFF_Y	0x1C
#define GYRO_MAX_LEN	0x200000	/* 2MB，与原版一致 */

static int gyro_enable		= 1;
static int gyro_mode;			/* 0: 正常 1: X/Y互换并取反 2: 双取反 3: 只互换 */
static u32 gyro_par_a;			/* float 位模式：X 偏移量（原版 dword_1EF9C） */
static u32 gyro_par_b;			/* float 位模式：Y 偏移量（原版 dword_1EFA0） */
static int gyro_type_mask	= 0x3;	/* bit0: type 4, bit1: type 16 */

static unsigned int g_gyro_seq;

unsigned int memx_gyro_stamp(void)
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

/* 位级取负：等价于把 float 的符号位翻转（比 mode 里 ^0x80000000 更准确） */
/*
 * IEEE754 单精度加法（纯整数实现，内核里不能用浮点）。
 *
 * 原版 0x910 的那两个参数是 **float 偏移量**，不是百分比缩放：
 * 对每个采样做 sample + offset。之前按百分比乘法处理，
 * 客户端送来的 1.0f(0x3F800000) 被当成十亿倍，画面直接乱掉、方向反了。
 */
static u32 memx_f32_add(u32 a, u32 b)
{
	int ea = (a >> 23) & 0xff, eb = (b >> 23) & 0xff;
	u32 ma = a & 0x7fffff, mb = b & 0x7fffff;
	u32 sa = a >> 31, sb = b >> 31, s, m;
	int e, d;

	if (!(a & 0x7fffffff))
		return b;
	if (!(b & 0x7fffffff))
		return a;
	if (ea == 0xff || eb == 0xff)
		return a;			/* NaN/Inf：原样 */

	if (ea)
		ma |= 0x800000;
	else
		ea = 1;
	if (eb)
		mb |= 0x800000;
	else
		eb = 1;

	if (ea >= eb) {
		e = ea;
		d = ea - eb;
		mb >>= (d > 31 ? 31 : d);
	} else {
		e = eb;
		d = eb - ea;
		ma >>= (d > 31 ? 31 : d);
	}

	if (sa == sb) {
		s = sa;
		m = ma + mb;
		if (m & 0x1000000) {
			m >>= 1;
			e++;
		}
	} else {
		if (ma >= mb) {
			s = sa;
			m = ma - mb;
		} else {
			s = sb;
			m = mb - ma;
		}
		if (!m)
			return 0;
		while (!(m & 0x800000)) {
			m <<= 1;
			e--;
		}
	}

	if (e <= 0)
		return s << 31;
	if (e >= 0xff)
		return (s << 31) | 0x7f800000;
	return (s << 31) | ((u32)e << 23) | (m & 0x7fffff);
}

static inline u32 memx_f32_neg(u32 bits)
{
	return bits ^ 0x80000000u;
}

static inline bool memx_type_match(u32 type)
{
	return (type == 4 && (gyro_type_mask & 1)) ||
	       (type == 16 && (gyro_type_mask & 2));
}

bool memx_is_gyro_packet(const void *hdr, size_t len)
{
	const u8 *p = hdr;
	u32 type;

	if (!gyro_enable || len < GYRO_REC_SIZE || len % GYRO_REC_SIZE)
		return false;
	if (len > GYRO_MAX_LEN)
		return false;

	memcpy(&type, p + GYRO_OFF_TYPE, sizeof(type));
	return memx_type_match(type);
}

/*
 * 就地改写一个包，返回改写的记录数（负数=失败）。
 */
int memx_gyro_patch(unsigned int seq, void __user *data, size_t len)
{
	u8 *kbuf;
	size_t i, nrec;
	u32 off_x, off_y;
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

	/* 原版语义：mode 变换的是**偏移参数**，不是采样值 */
	off_x = gyro_par_a;
	off_y = gyro_par_b;
	switch (gyro_mode) {
	case 3: {			/* 只互换 */
		u32 t = off_x;
		off_x = off_y;
		off_y = t;
		break;
	}
	case 2:				/* 双取反 */
		off_x = memx_f32_neg(off_x);
		off_y = memx_f32_neg(off_y);
		break;
	case 1: {			/* 互换并取反 */
		u32 t = memx_f32_neg(off_y);
		off_y = memx_f32_neg(off_x);
		off_x = t;
		break;
	}
	default:
		break;
	}

	nrec = len / GYRO_REC_SIZE;
	for (i = 0; i < nrec; i++) {
		u8 *rec = kbuf + i * GYRO_REC_SIZE;
		u32 type, bx, by;

		memcpy(&type, rec + GYRO_OFF_TYPE, 4);
		if (!memx_type_match(type))
			continue;

		memcpy(&bx, rec + GYRO_OFF_X, 4);
		memcpy(&by, rec + GYRO_OFF_Y, 4);

		bx = memx_f32_add(bx, off_x);
		by = memx_f32_add(by, off_y);

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
void memx_sendto_probe(void __user *buf, size_t len)
{
	u8 probe[GYRO_REC_SIZE];

	if (!gyro_enable || !buf)
		return;
	if (len < GYRO_REC_SIZE || len % GYRO_REC_SIZE || len > GYRO_MAX_LEN)
		return;
	if (copy_from_user(probe, buf, sizeof(probe)))
		return;
	if (!memx_is_gyro_packet(probe, len))
		return;

	memx_gyro_patch(memx_gyro_stamp(), buf, len);
}

/* ================================================================== */
/* 运行期配置（替代 .ko 版的 ioctl 写全局变量）                         */
/* ================================================================== */
void memx_gyro_set(int enable, int mode, int sx, int sy, int mask)
{
	WRITE_ONCE(gyro_enable, enable);
	WRITE_ONCE(gyro_mode, mode);
	WRITE_ONCE(gyro_par_a, (u32)sx);
	WRITE_ONCE(gyro_par_b, (u32)sy);
	WRITE_ONCE(gyro_type_mask, mask);
}
