// SPDX-License-Identifier: GPL-2.0
/*
 * kairos_auth.c — 设备绑定认证（从 _xd3f96adb... @0x9358 + _x41bbebc... @0x9260 转写）
 *
 * ── 它到底在干嘛 ──────────────────────────────────────────────
 * 不是"密码校验"，是**设备指纹绑定**：
 *   1. 依次尝试读 14 个设备序列号路径（eMMC cid / sda serial / DT serial-number）
 *   2. 读到就拼成  "DEV_<序列号>_KEY"
 *      一个都读不到就退化成 "KERN_<进程名>_FALLBACK"
 *   3. 对该字符串做 **base64**
 *   4. 和客户端在 ioctl 0x800 里送来的那串（前 64 字节）做 strcmp
 *
 * 所以它的作用有两个：
 *   - 保证驱动只在"预期设备"上工作（拷到别的机器上就认证不过）
 *   - 让第三方没法随便写个客户端就调用 —— 必须先拿到这台机器的序列号
 *
 * 注意：**这不是权限控制**。序列号在 root 下都能读，magic 又是明文回传的
 * 32 位整数，所以真正的门槛只有"能读到序列号"。如果要提高门槛，得换成
 * 服务端下发的一次性挑战（跟 loader 那套 V2 协商一样）。
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mm.h>

#include "kairos.h"

/* 原版 read_and_clean_file()：读到缓冲区并去掉尾部空白/换行 */
static int kairos_read_clean(const char *path, char *buf, size_t bufsz)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;
	size_t i, q = 0;

	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return -ENOENT;

	n = kernel_read(f, buf, bufsz - 1, &pos);
	fput(f);
	if (n <= 0)
		return -EIO;

	/*
	 * 只保留可打印字符（0x21..0x7e），其余一律丢掉。
	 *
	 * 为什么不能按 C 字符串处理：/sys/block/sda/device/inquiry 的内容是
	 *     00 00 06 02 1f 00 00 02 "MICRON  " "MT256GBGBB2U41  " "0101"
	 * 首字节就是 0x00，按 NUL 截断会得到空串。而客户端（kprobe 抓包验证）
	 * 拼出的 key 是 DEV_MICRONMT256GBGBB2U410101_KEY ——
	 * 二进制头被丢弃、空格也被丢弃，只留可打印字符。
	 */
	for (i = 0; i < (size_t)n; i++) {
		unsigned char c = (unsigned char)buf[i];

		if (c > 0x20 && c < 0x7f)
			buf[q++] = (char)c;
	}
	buf[q] = 0;

	return (int)q;
}

/* 原版 14 个路径，前 6 个要求 len > 15，后 8 个要求 len > 7 */
struct kairos_sn_src {
	const char	*path;
	unsigned int	min_len;
};

static const struct kairos_sn_src kairos_sn_srcs[] = {
	{ "/sys/block/mmcblk0/device/cid", 15 },
	{ "/sys/class/mmc_host/mmc0/mmc0:0001/cid", 15 },
	{ "/sys/bus/mmc/devices/mmc0:0001/cid", 15 },
	{ "/sys/devices/platform/soc/7824900.sdhci/mmc_host/mmc0/mmc0:0001/cid", 15 },
	{ "/sys/devices/platform/soc/7c4000.sdhci/mmc_host/mmc0/mmc0:0001/cid", 15 },
	{ "/sys/devices/soc/7824900.sdhci/mmc_host/mmc0/mmc0:0001/cid", 15 },
	{ "/sys/block/sda/device/serial", 7 },
	{ "/sys/class/scsi_device/0:0:0:0/device/serial", 7 },
	{ "/sys/block/sda/device/inquiry", 7 },
	{ "/sys/devices/platform/soc/1d84000.ufshc/host0/target0:0:0/0:0:0:0/serial", 7 },
	{ "/sys/firmware/devicetree/base/serial-number", 7 },
	{ "/sys/firmware/devicetree/base/chosen/serial-number", 7 },
	{ "/proc/device-tree/serial-number", 7 },
	{ "/proc/device-tree/chosen/serial-number", 7 },
};

int kairos_expected_key(char *out, size_t outsz)
{
	char sn[64];
	int i, n;

	for (i = 0; i < ARRAY_SIZE(kairos_sn_srcs); i++) {
		n = kairos_read_clean(kairos_sn_srcs[i].path, sn, sizeof(sn));
		if (n > (int)kairos_sn_srcs[i].min_len)
			return snprintf(out, outsz, "DEV_%s_KEY", sn);
	}

	/* 全部读不到：退化成用进程名（原版读 current+2160+8+130，即 comm 尾部） */
	return snprintf(out, outsz, "KERN_%s_FALLBACK", current->comm);
}

/* 标准 base64（原版 _x41bbebc... 就是教科书实现，含 '=' 填充） */
static const char kairos_b64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void kairos_base64(char *out, const u8 *in, int len)
{
	int i = 0, o = 0;

	while (i < len) {
		u32 v = (u32)in[i] << 16;

		if (i + 1 < len)
			v |= (u32)in[i + 1] << 8;
		if (i + 2 < len)
			v |= in[i + 2];

		out[o++] = kairos_b64tab[(v >> 18) & 0x3F];
		out[o++] = kairos_b64tab[(v >> 12) & 0x3F];
		out[o++] = (i + 1 < len) ? kairos_b64tab[(v >> 6) & 0x3F] : '=';
		out[o++] = (i + 2 < len) ? kairos_b64tab[v & 0x3F] : '=';
		i += 3;
	}
	out[o] = 0;
}

/*
 * 返回 0 = 通过。-EINVAL 表示本机拿不到序列号，-EACCES 表示不匹配。
 * 注意原版有个坑：生成的 key 长度恰好 64 时会走 fortify_panic（strnlen 找不到 NUL），
 * 这里直接判掉并返回 -EINVAL，避免把机器搞挂。
 */
int kairos_auth_check(const u8 *blob)
{
	char expect[80], b64[128];
	int n;

	n = kairos_expected_key(expect, sizeof(expect));
	if (n <= 0 || n >= 64)
		return -EINVAL;

	kairos_base64(b64, (const u8 *)expect, n);

	/* 只比前 KAIROS_KEY_LEN(64) 字节：客户端只送 64 字节，
	 * 原版用 sizeof(b64)=128 比会读越过用户缓冲末尾 */
	if (strncmp((const char *)blob, b64, KAIROS_KEY_LEN))
		return -EACCES;

	return 0;
}
