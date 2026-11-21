// SPDX-License-Identifier: GPL-2.0
/*
 * memx_touch.c —— 触摸注入（0x809 / 0x810 / 0x811 / 0x812 / 0x814 / 0x817）
 *
 * 与原版一致的完整链路：
 *
 *   0x809 attach(w, h, orient)
 *     ├─ 在 input_class 里挑一块真实触摸屏（带 ABS_MT_POSITION_X/Y，名字不含 uinput）
 *     ├─ 在**调用者进程**的 fd 表里找到指向该触摸屏 evdev 节点的 fd
 *     ├─ fget 拿到 struct file*，保存原 f_op
 *     ├─ 复制整张 fops 表，替换 .read / .poll
 *     └─ 换上 file->f_op
 *
 *   0x810 down / 0x811 move / 0x812 up
 *     └─ 向触摸屏 input_dev 打 MT 协议 B 事件，同时把同样的事件压进队列，
 *        客户端通过被钩住的 read 就能读到，poll 返回 EPOLLIN
 *
 *   0x814 / 0x817 detach
 *     └─ 还原 f_op、释放 file 引用
 *
 * 参数约定（12 字节）：
 *   0x809 {u32 screen_w; u32 screen_h; u32 orientation}
 *   0x810/0x811 {u32 slot; u32 x; u32 y}
 *   0x812 {u32 slot}
 *
 * 坐标：客户端给屏幕像素，按 px * (hw_max - hw_min) / screen + hw_min 映射到
 * 触摸屏 ABS 量程（等价于原版 transform_coordinates）。
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/major.h>
#include <linux/poll.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>

#include "memx.h"

/* built-in 链接，不需要 EXPORT_SYMBOL */
extern struct class input_class;

#define MEMX_TOUCH_SLOTS	10
#define MEMX_EVQ_MAX		32

static struct input_dev	*g_tdev;
static DEFINE_MUTEX(g_tlock);

static int	g_screen_w;
static int	g_screen_h;
static int	g_orient;		/* 0/1/2/3 == Surface.ROTATION_0/90/180/270 */
static int	g_hw_min_x, g_hw_max_x;
static int	g_hw_min_y, g_hw_max_y;

static bool	g_slot_down[MEMX_TOUCH_SLOTS];
static u32	g_slot_tid[MEMX_TOUCH_SLOTS];
static u32	g_tid_counter;

/* ---- fops 钩子 ---- */
static struct file		*g_hooked_file;
static const struct file_operations *g_orig_fop;
static struct file_operations	 g_hooked_fops;
static ssize_t (*g_old_read)(struct file *, char __user *, size_t, loff_t *);
static __poll_t (*g_old_poll)(struct file *, struct poll_table_struct *);

/* 送给客户端的事件队列 */
static struct input_event	g_evq[MEMX_EVQ_MAX];
static int			g_evq_n;

/* ================================================================== */
/* 设备与 fd 定位                                                      */
/* ================================================================== */
static int memx_touch_match(struct device *dev, void *data)
{
	struct input_dev *idev = to_input_dev(dev);
	struct input_dev **out = (struct input_dev **)data;

	if (!idev)
		return 0;
	if (!test_bit(ABS_MT_POSITION_X, idev->absbit) ||
	    !test_bit(ABS_MT_POSITION_Y, idev->absbit))
		return 0;
	if (idev->name && strstr(idev->name, "uinput"))
		return 0;

	*out = idev;
	return 1;
}

struct memx_evdev_lookup {
	struct device	*parent;
	dev_t		devt;
};

static int memx_evdev_match(struct device *dev, void *data)
{
	struct memx_evdev_lookup *l = data;

	if (MAJOR(dev->devt) != INPUT_MAJOR)
		return 0;
	if (dev->parent != l->parent)
		return 0;

	l->devt = dev->devt;
	return 1;
}

/* 在调用者自己的 fd 表里找指向 devt 的那个 fd */
static int memx_find_fd(dev_t devt)
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	int found = -1;
	unsigned int i;

	if (!files)
		return -1;

	rcu_read_lock();
	fdt = files_fdtable(files);
	for (i = 0; i < fdt->max_fds; i++) {
		struct file *fp = rcu_dereference_raw(fdt->fd[i]);
		struct inode *ino;

		if (!fp)
			continue;
		ino = file_inode(fp);
		if (!ino || !S_ISCHR(ino->i_mode))
			continue;
		if (ino->i_rdev != devt)
			continue;
		found = (int)i;
		break;
	}
	rcu_read_unlock();

	return found;
}

/* ================================================================== */
/* 被钩住的 read / poll                                                */
/* ================================================================== */
static ssize_t memx_hooked_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	size_t n;
	int k;

	mutex_lock(&g_tlock);
	if (g_evq_n > 0) {
		n = min_t(size_t, count,
			  (size_t)g_evq_n * sizeof(struct input_event));
		k = (int)(n / sizeof(struct input_event));
		if (!k) {
			mutex_unlock(&g_tlock);
			return -EINVAL;
		}
		if (copy_to_user(buf, g_evq, n)) {
			mutex_unlock(&g_tlock);
			return -EFAULT;
		}
		memmove(g_evq, g_evq + k,
			(size_t)(g_evq_n - k) * sizeof(struct input_event));
		g_evq_n -= k;
		mutex_unlock(&g_tlock);
		return (ssize_t)n;
	}
	mutex_unlock(&g_tlock);

	return g_old_read ? g_old_read(file, buf, count, ppos) : -EINVAL;
}

static __poll_t memx_hooked_poll(struct file *file, struct poll_table_struct *pt)
{
	__poll_t ret = g_old_poll ? g_old_poll(file, pt) : 0;

	if (READ_ONCE(g_evq_n) > 0)
		ret |= EPOLLIN | EPOLLRDNORM;

	return ret;
}

/* 把事件同时投进队列，供客户端 read 取走 */
static void memx_queue_event(unsigned int type, unsigned int code, int value)
{
	if (g_evq_n >= MEMX_EVQ_MAX)
		return;

	memset(&g_evq[g_evq_n], 0, sizeof(struct input_event));
	g_evq[g_evq_n].type = type;
	g_evq[g_evq_n].code = code;
	g_evq[g_evq_n].value = value;
	g_evq_n++;
}

static void memx_emit(unsigned int type, unsigned int code, int value)
{
	if (!g_tdev)
		return;

	input_event(g_tdev, type, code, value);
	memx_queue_event(type, code, value);
}

/* 有 ABS_MT_PRESSURE 轴就打满：否则 InputReader 可能把这一指判成 hover，
 * 事件到了 evdev 但上层应用（尤其游戏）根本不响应。 */
static void memx_emit_pressure(void)
{
	int max;

	if (!g_tdev)
		return;
	max = input_abs_get_max(g_tdev, ABS_MT_PRESSURE);
	if (max > 0)
		memx_emit(EV_ABS, ABS_MT_PRESSURE, max);
}

static void memx_emit_pressure_zero(void)
{
	if (g_tdev && input_abs_get_max(g_tdev, ABS_MT_PRESSURE) > 0)
		memx_emit(EV_ABS, ABS_MT_PRESSURE, 0);
}

/* ================================================================== */
/* 坐标映射                                                            */
/* ================================================================== */
/*
 * 逻辑屏坐标 -> 触摸屏自然坐标。
 *
 * 触摸屏的 ABS 量程定义在**面板自然方向**上（这台机器是竖屏：X=1904*10, Y=3040*10），
 * 而客户端给的是**旋转后**的逻辑坐标（横屏 3040x1904），所以必须按 orientation
 * 做一次旋转/镜像，再线性映射进 ABS 量程。
 *
 * 实测（orientation=1，ROT_90）：
 *     lx = ABS_Y / 10
 *     ly = 1904 - ABS_X / 10
 *   => 自然系  nx = H - ly , ny = lx
 */
static int memx_scale(int v, int src_max, int hw_min, int hw_max);

static void memx_map_point(int x, int y, int *ax, int *ay)
{
	int nx, ny, nw, nh;

	switch (g_orient & 3) {
	case 1:			/* ROT_90 */
		nx = g_screen_h - y;
		ny = x;
		nw = g_screen_h;	/* 自然宽度 == 逻辑高度 */
		nh = g_screen_w;
		break;
	case 3:			/* ROT_270 */
		nx = y;
		ny = g_screen_w - x;
		nw = g_screen_h;
		nh = g_screen_w;
		break;
	case 2:			/* ROT_180 */
		nx = g_screen_w - x;
		ny = g_screen_h - y;
		nw = g_screen_w;
		nh = g_screen_h;
		break;
	default:		/* ROT_0 */
		nx = x;
		ny = y;
		nw = g_screen_w;
		nh = g_screen_h;
		break;
	}

	*ax = memx_scale(nx, nw, g_hw_min_x, g_hw_max_x);
	*ay = memx_scale(ny, nh, g_hw_min_y, g_hw_max_y);
}

/* 让 (screen_w, screen_h) 与客户端一致：旋转时保证是“横屏”语义 */
static void memx_normalize_dims(void)
{
	if ((g_orient & 1) && g_screen_w < g_screen_h) {
		int t = g_screen_w;
		g_screen_w = g_screen_h;
		g_screen_h = t;
	}
}

static int memx_scale(int v, int src_max, int hw_min, int hw_max)
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
/* attach / detach                                                     */
/* ================================================================== */
static void memx_touch_unhook_locked(void)
{
	int i;

	if (g_tdev) {
		for (i = 0; i < MEMX_TOUCH_SLOTS; i++) {
			if (!g_slot_down[i])
				continue;
			input_event(g_tdev, EV_ABS, ABS_MT_SLOT, i);
			input_event(g_tdev, EV_ABS, ABS_MT_TRACKING_ID, -1);
			g_slot_down[i] = false;
		}
		input_event(g_tdev, EV_KEY, BTN_TOUCH, 0);
		input_event(g_tdev, EV_SYN, SYN_REPORT, 0);
	}

	if (g_hooked_file) {
		WRITE_ONCE(g_hooked_file->f_op, g_orig_fop);
		fput(g_hooked_file);
		g_hooked_file = NULL;
		g_orig_fop = NULL;
	}

	if (g_tdev) {
		put_device(&g_tdev->dev);
		g_tdev = NULL;
	}

	g_evq_n = 0;
	g_old_read = NULL;
	g_old_poll = NULL;
}

int memx_touch_attach(int screen_w, int screen_h, int orientation)
{
	struct input_dev *dev = NULL;
	struct memx_evdev_lookup lk;
	struct file *fp;
	int fd;

	mutex_lock(&g_tlock);

	if (g_tdev || g_hooked_file)
		memx_touch_unhook_locked();

	g_screen_w = screen_w;
	g_screen_h = screen_h;
	g_orient = orientation & 3;

	class_for_each_device(&input_class, NULL, &dev, memx_touch_match);
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

	/*
	 * 兜底：调用方把 orientation 传 0（或没传），但面板自然方向与逻辑方向
	 * 的纵横比不一致 —— 说明画面其实是转过的，按 90° 处理，
	 * 否则整块触摸会转置（正中点还能对上，越靠边错得越多）。
	 */
	{
		int span_x = g_hw_max_x - g_hw_min_x;
		int span_y = g_hw_max_y - g_hw_min_y;

		if ((g_orient & 3) == 0 && span_x > 0 && span_y > 0 &&
		    ((span_x > span_y) != (g_screen_w > g_screen_h)))
			g_orient = 1;
	}

	memx_normalize_dims();

#ifdef MEMX_VERBOSE
	pr_info("memx_touch: dev=%s abs_x=[%d,%d] abs_y=[%d,%d] screen=%dx%d orient=%d\n",
		dev->name ? dev->name : "?",
		g_hw_min_x, g_hw_max_x, g_hw_min_y, g_hw_max_y,
		g_screen_w, g_screen_h, g_orient);
#endif

	memset(g_slot_down, 0, sizeof(g_slot_down));
	memset(g_slot_tid, 0, sizeof(g_slot_tid));
	g_tid_counter = 0;
	g_evq_n = 0;

	/*
	 * 找出该触摸屏对应的 evdev 字符设备号，再在调用者 fd 表里定位。
	 * 找不到也不失败 —— 事件注入本身仍然可用，只是客户端读不到回投。
	 */
	lk.parent = &dev->dev;
	lk.devt = 0;
	class_for_each_device(&input_class, NULL, &lk, memx_evdev_match);

	fd = lk.devt ? memx_find_fd(lk.devt) : -1;
	if (fd < 0) {
		mutex_unlock(&g_tlock);
		return 0;
	}

	fp = fget(fd);
	if (!fp) {
		mutex_unlock(&g_tlock);
		return 0;
	}

	/* 复制 fops 并替换 read/poll */
	g_orig_fop = fp->f_op;
	memcpy(&g_hooked_fops, g_orig_fop, sizeof(g_hooked_fops));
	g_old_read = g_hooked_fops.read;
	g_old_poll = g_hooked_fops.poll;
	g_hooked_fops.read = memx_hooked_read;
	g_hooked_fops.poll = memx_hooked_poll;

	WRITE_ONCE(fp->f_op, &g_hooked_fops);
	g_hooked_file = fp;

	mutex_unlock(&g_tlock);
	return 0;
}

int memx_touch_down(int slot, int x, int y)
{
	int hx, hy;

	if (slot < 0 || slot >= MEMX_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}

	memx_map_point(x, y, &hx, &hy);

	if (!g_slot_down[slot]) {
		g_slot_down[slot] = true;
		g_slot_tid[slot] = ++g_tid_counter;
	}

	memx_emit(EV_ABS, ABS_MT_SLOT, slot);
	memx_emit(EV_ABS, ABS_MT_TRACKING_ID, (int)g_slot_tid[slot]);
	memx_emit(EV_ABS, ABS_MT_POSITION_X, hx);
	memx_emit(EV_ABS, ABS_MT_POSITION_Y, hy);
	memx_emit_pressure();
	memx_emit(EV_KEY, BTN_TOUCH, 1);
	memx_emit(EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int memx_touch_move(int slot, int x, int y)
{
	int hx, hy;

	if (slot < 0 || slot >= MEMX_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}
	if (!g_slot_down[slot]) {
		mutex_unlock(&g_tlock);
		return -EINVAL;
	}

	memx_map_point(x, y, &hx, &hy);

	memx_emit(EV_ABS, ABS_MT_SLOT, slot);
	memx_emit(EV_ABS, ABS_MT_POSITION_X, hx);
	memx_emit(EV_ABS, ABS_MT_POSITION_Y, hy);
	memx_emit_pressure();
	memx_emit(EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int memx_touch_up(int slot)
{
	int i, remain = 0;

	if (slot < 0 || slot >= MEMX_TOUCH_SLOTS)
		return -EINVAL;

	mutex_lock(&g_tlock);
	if (!g_tdev) {
		mutex_unlock(&g_tlock);
		return -ENODEV;
	}

	if (g_slot_down[slot]) {
		g_slot_down[slot] = false;
		memx_emit(EV_ABS, ABS_MT_SLOT, slot);
		memx_emit(EV_ABS, ABS_MT_TRACKING_ID, -1);
	}

	for (i = 0; i < MEMX_TOUCH_SLOTS; i++)
		if (g_slot_down[i])
			remain++;

	if (!remain) {
		memx_emit_pressure_zero();
		memx_emit(EV_KEY, BTN_TOUCH, 0);
	}

	memx_emit(EV_SYN, SYN_REPORT, 0);

	mutex_unlock(&g_tlock);
	return 0;
}

int memx_touch_detach(void)
{
	mutex_lock(&g_tlock);
	memx_touch_unhook_locked();
	mutex_unlock(&g_tlock);
	return 0;
}
