// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_touch.c —— 触摸注入（0x809 / 0x810 / 0x811 / 0x812 / 0x814 / 0x817）
 *
 * 和原版同样的做法：**不建 uinput 虚拟设备**，而是找到系统里真实的触摸屏
 * input_dev，直接往里打 MT 协议 B 的事件。好处是 /dev/input 下不会多出
 * 可疑节点，只需要普通的事件流就能被 input 子系统正常分发。
 *
 * 原版用 kallsyms_lookup_name 找 input_dev_list（未导出符号）；
 * 我们是 built-in，直接引用 input_class 遍历即可，不需要符号解析。
 *
 * 参数约定（12 字节）：
 *   0x809  attach  {u32 screen_w; u32 screen_h; u32 orientation}
 *   0x810  down    {u32 slot; u32 x; u32 y}
 *   0x811  move    {u32 slot; u32 x; u32 y}
 *   0x812  up      {u32 slot}
 *   0x814 / 0x817  detach（无参数）
 *
 * 坐标：客户端给的是屏幕像素，按
 *   hw = px * (hw_max - hw_min) / screen + hw_min
 * 线性映射到触摸屏的 ABS 量程（与原版 transform_coordinates 一致）。
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/uaccess.h>

#include "kairos.h"

/* built-in 链接，不需要 EXPORT_SYMBOL */
extern struct class input_class;

#define KAIROS_TOUCH_SLOTS	10

static struct input_dev	*g_tdev;
static DEFINE_MUTEX(g_tlock);

static int	g_screen_w;		/* 客户端坐标系宽度 */
static int	g_screen_h;
static int	g_hw_min_x, g_hw_max_x;
static int	g_hw_min_y, g_hw_max_y;

static bool	g_slot_down[KAIROS_TOUCH_SLOTS];
static u32	g_slot_tid[KAIROS_TOUCH_SLOTS];
static u32	g_tid_counter;

/* ================================================================== */
/* 设备发现                                                            */
/* ================================================================== */
static int kairos_touch_match(struct device *dev, void *data)
{
	struct input_dev *idev = to_input_dev(dev);
	struct input_dev **out = (struct input_dev **)data;

	if (!idev)
		return 0;
	/* 必须支持多点坐标 */
	if (!test_bit(ABS_MT_POSITION_X, idev->absbit) ||
	    !test_bit(ABS_MT_POSITION_Y, idev->absbit))
		return 0;
	/* 跳过我们自己可能造出来的节点 */
	if (idev->name && strstr(idev->name, "uinput"))
		return 0;

	*out = idev;
	return 1;			/* 找到就停 */
}

static void kairos_touch_release_locked(void)
{
	int i;

	if (!g_tdev)
		return;

	for (i = 0; i < KAIROS_TOUCH_SLOTS; i++) {
		if (!g_slot_down[i])
			continue;
		input_event(g_tdev, EV_ABS, ABS_MT_SLOT, i);
		input_event(g_tdev, EV_ABS, ABS_MT_TRACKING_ID, -1);
		g_slot_down[i] = false;
	}
	input_event(g_tdev, EV_KEY, BTN_TOUCH, 0);
	input_event(g_tdev, EV_SYN, SYN_REPORT, 0);

	put_device(&g_tdev->dev);
	g_tdev = NULL;
}

/* ================================================================== */
/* 坐标映射                                                            */
/* ================================================================== */
static int kairos_scale(int v, int src_max, int hw_min, int hw_max)
{
	if (src_max <= 0 || hw_max <= hw_min)
		return v;

	if (v < 0)
		v = 0;
	if (v > src_max)
		v = src_max;

	return (int)((s64)v * (hw_max - hw_min) / src_max + hw_min);
}

/* ================================================================== */
/* 对外接口                                                            */
/* ================================================================== */
int kairos_touch_attach(int screen_w, int screen_h, int orientation)
{
	struct input_dev *dev = NULL;

	mutex_lock(&g_tlock);

	if (g_tdev)
		kairos_touch_release_locked();

	g_screen_w = screen_w;
	g_screen_h = screen_h;
	(void)orientation;		/* 原版按方向做旋转，先按竖屏映射 */

	class_for_each_device(&input_class, NULL, &dev, kairos_touch_match);
	if (!dev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}

	get_device(&dev->dev);
	g_tdev = dev;

	g_hw_min_x = input_abs_get_min(dev, ABS_MT_POSITION_X);
	g_hw_max_x = input_abs_get_max(dev, ABS_MT_POSITION_X);
	g_hw_min_y = input_abs_get_min(dev, ABS_MT_POSITION_Y);
	g_hw_max_y = input_abs_get_max(dev, ABS_MT_POSITION_Y);

	memset(g_slot_down, 0, sizeof(g_slot_down));
	memset(g_slot_tid, 0, sizeof(g_slot_tid));
	g_tid_counter = 0;

	mutex_unlock(&g_tlock);
	return 0;
}

int kairos_touch_down(int slot, int x, int y)
{
	int hx, hy;

	if (slot < 0 || slot >= KAIROS_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}

	hx = kairos_scale(x, g_screen_w, g_hw_min_x, g_hw_max_x);
	hy = kairos_scale(y, g_screen_h, g_hw_min_y, g_hw_max_y);

	if (!g_slot_down[slot]) {
		g_slot_down[slot] = true;
		g_slot_tid[slot] = ++g_tid_counter;
	}

	input_event(g_tdev, EV_ABS, ABS_MT_SLOT, slot);
	input_event(g_tdev, EV_ABS, ABS_MT_TRACKING_ID, (int)g_slot_tid[slot]);
	input_event(g_tdev, EV_ABS, ABS_MT_POSITION_X, hx);
	input_event(g_tdev, EV_ABS, ABS_MT_POSITION_Y, hy);
	input_event(g_tdev, EV_KEY, BTN_TOUCH, 1);
	input_event(g_tdev, EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int kairos_touch_move(int slot, int x, int y)
{
	int hx, hy;

	if (slot < 0 || slot >= KAIROS_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}
	if (!g_slot_down[slot]) {
		mutex_unlock(&g_tlock);
		return -EINVAL;		/* 没按下就移动，忽略 */
	}

	hx = kairos_scale(x, g_screen_w, g_hw_min_x, g_hw_max_x);
	hy = kairos_scale(y, g_screen_h, g_hw_min_y, g_hw_max_y);

	input_event(g_tdev, EV_ABS, ABS_MT_SLOT, slot);
	input_event(g_tdev, EV_ABS, ABS_MT_POSITION_X, hx);
	input_event(g_tdev, EV_ABS, ABS_MT_POSITION_Y, hy);
	input_event(g_tdev, EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int kairos_touch_up(int slot)
{
	int i, remain = 0;

	if (slot < 0 || slot >= KAIROS_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}

	if (g_slot_down[slot]) {
		g_slot_down[slot] = false;
		input_event(g_tdev, EV_ABS, ABS_MT_SLOT, slot);
		input_event(g_tdev, EV_ABS, ABS_MT_TRACKING_ID, -1);
	}

	for (i = 0; i < KAIROS_TOUCH_SLOTS; i++)
		if (g_slot_down[i])
			remain++;

	/* 全部抬起才发 BTN_TOUCH=0，多点时保持按下 */
	if (!remain)
		input_event(g_tdev, EV_KEY, BTN_TOUCH, 0);

	input_event(g_tdev, EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int kairos_touch_detach(void)
{
	mutex_lock(&g_tlock);
	kairos_touch_release_locked();
	mutex_unlock(&g_tlock);
	return 0;
}
