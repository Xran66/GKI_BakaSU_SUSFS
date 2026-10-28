// SPDX-License-Identifier: GPL-2.0
// prop_spoof.c —— 定向属性表/cpuinfo 伪装内核模块（v2：LSM 按 app 补丁）
//
// v1 教训：
//   · 全局 hook /dev/__properties__（i_fop/i_op 替换）会把 init.svc/sys.*
//     等开机动态属性冻在快照上 —— 软重启后开机流程卡死。
//   · arm64 6.6 set_memory_* 只允许 vmalloc，内核 rodata 改不动。
//   · app 的属性区映射继承自 zygote，全局换文件也影响不到已启动的 zygote。
//
// v2 方案（按 app，零开机影响）：
//   1. 枚举 /dev/__properties__，为有假内容的文件建立 {真inode → 假文件} 表
//      （假文件 = fake_dir 下的同名 V2545A 属性区文件，本模块持有引用）。
//   2. 通过 LSM task_fix_setuid 钩子（security_hook_heads 是数据指针，合法
//      扩展点，KernelSU LKM 同款机制）：app 被 zygote setuid 的瞬间、其任何
//      代码运行之前，遍历该进程的 vma，把属性区 vma 的 backing file 换成
//      假文件并 zap 旧页 —— 只有目标 uid 的进程读到 V2545A 表，其他进程
//      （含开机全程）完全不受影响。
//   3. /proc/cpuinfo：PDE->proc_ops 指针按 uid 过滤（v1 已验证）。
//
// 加载（无 ksud 依赖，post-fs-data 可直接 insmod；地址参数由加载脚本从
// 当前开机 kallsyms 提取）：
//   insmod prop_spoof.ko target_uid=10266 proc_root_addr=0x.. shh_addr=0x.. \
//     fake_dir=/data/adb/prop_spoof/fake_props

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/sched/mm.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("");
MODULE_AUTHOR("");

/* ==================================================================
 * 内建模式（PROP_SPOOF_BUILTIN=y，编进 vmlinux）
 * ------------------------------------------------------------------
 * 与 .ko 的区别只有两点：
 *   1. 不需要 kallsyms 地址参数：proc_root / security_hook_heads /
 *      filp_open 都是同一 vmlinux 的符号，链接器直接解析
 *   2. 参数不能从 insmod 命令行传：改为用户态脚本经
 *      /proc/prop_spoof_cfg 注入（fakedir / uids / build / start）
 * 其余逻辑完全一致。
 * ================================================================== */
#ifdef PROP_SPOOF_BUILTIN
extern struct proc_dir_entry proc_root;
extern struct security_hook_heads security_hook_heads;

#define PROP_PROC_ROOT() ((struct proc_dir_entry *)&proc_root)
#define PROP_SHH()       (&security_hook_heads)
#else
#define PROP_PROC_ROOT() ((struct proc_dir_entry *)proc_root_addr)
#define PROP_SHH()       ((struct security_hook_heads *)shh_addr)
#endif

/*
 * arm64 内核（CONFIG_ARM64_MODULE_PLTS=y）要求模块带这三个 NOBITS 节。
 */
#ifndef PROP_SPOOF_BUILTIN
asm(".section .plt,\"\",%nobits\n"
    ".section .init.plt,\"\",%nobits\n"
    ".section .text.ftrace_trampoline,\"\",%nobits\n");
#endif

#ifndef PROP_SPOOF_BUILTIN
static const char __module_info_vermagic[] __used
	__attribute__((section(".modinfo"))) =
	"vermagic=6.6.118-android15-8-g350f378eb496-ab14943902-4k"
	" SMP preempt mod_unload modversions aarch64";
#endif

/* ihold 在 VFS 受控命名空间（普通 insmod 必需） */
#ifndef PROP_SPOOF_BUILTIN
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

/*
 * MODVERSIONS 内核要求 __versions 里有正确的 module_layout CRC，
 * 否则 GKI（MODULE_FORCE_LOAD=n）静默 -ENOEXEC。CRC 是编译期常量。
 */
#ifndef MODULE_LAYOUT_CRC
#define MODULE_LAYOUT_CRC 0x4e276f37
#endif
#ifndef PROP_SPOOF_BUILTIN
static const struct modversion_info __module_versions[] __used
	__attribute__((section("__versions"))) = {
	{ MODULE_LAYOUT_CRC, "module_layout" },
};
#endif

/* ---- 模块参数 ---- */
static int target_uid = -1;      /* 单目标 uid（-1 = 不用） */
static char *target_uids = "";   /* 逗号分隔多 uid，来自 target_app.txt */
static char *fake_dir = "/data/adb/prop_spoof/fake_props";
static char *sys_fake_dir = "";  /* /sys CPU 拓扑假文件根（cpu_fake/sys） */
static unsigned long proc_root_addr;  /* kallsyms: proc_root（未导出） */
static unsigned long shh_addr;        /* kallsyms: security_hook_heads（未导出） */
static unsigned long filp_open_addr;  /* kallsyms: filp_open（GKI 裁剪导出） */
module_param(target_uid, int, 0);
module_param(target_uids, charp, 0);
module_param(fake_dir, charp, 0);
/* ---- EGL 目录按 uid bind mount：目标 app 的 maps 里显示 mali 名 ----
 * 原理：setuid 瞬间 unshare(CLONE_NEWNS) 给 app 独立 mount ns，
 * 再把 egl_src_dir（mali 名 = adreno 内容的副本）bind 到 egl_dst_dir。
 * 只影响该 app，其他进程/系统零感知。 */
static int egl_mount;
static char *egl_src_dir = "/dev/eglspoof";
static char *egl_dst_dir = "/vendor/lib64/egl";
module_param(egl_mount, int, 0);
module_param(egl_src_dir, charp, 0);
module_param(egl_dst_dir, charp, 0);

#define EGL_CLONE_NEWNS 0x00020000
#define EGL_MS_BIND     0x00001000

/* GKI 裁剪导出/未导出符号：全部 kallsyms 地址参数化（ksud 模式先例） */
static unsigned long unshare_addr;    /* ksys_unshare */
static unsigned long kern_path_addr;  /* kern_path */
static unsigned long path_mount_addr; /* path_mount */
static unsigned long path_put_addr;   /* path_put */
static unsigned long ovr_cred_addr;   /* override_creds */
static unsigned long rev_cred_addr;   /* revert_creds */
static unsigned long init_cred_addr;  /* init_cred（数据） */
module_param(unshare_addr, ulong, 0);
module_param(kern_path_addr, ulong, 0);
module_param(path_mount_addr, ulong, 0);
module_param(path_put_addr, ulong, 0);
module_param(ovr_cred_addr, ulong, 0);
module_param(rev_cred_addr, ulong, 0);
module_param(init_cred_addr, ulong, 0);

typedef int (*unshare_fn)(unsigned long);
typedef int (*kern_path_fn)(const char *, unsigned int, struct path *);
typedef int (*path_mount_fn)(const char *, struct path *, const char *,
			     unsigned long, void *);
typedef void (*path_put_fn)(const struct path *);
typedef const struct cred *(*override_creds_fn)(const struct cred *);
typedef void (*revert_creds_fn)(const struct cred *);

/* 已挂过 shadow 的 mnt_ns 指针表（防重复挂载） */
#define EGL_NS_MAX 32
static void *egl_ns_list[EGL_NS_MAX];
static int egl_ns_n;
static DEFINE_MUTEX(egl_ns_lock);

static bool egl_ns_done(void)
{
	bool done = false;
	int i;

	mutex_lock(&egl_ns_lock);
	for (i = 0; i < egl_ns_n; i++)
		if (egl_ns_list[i] == current->nsproxy->mnt_ns)
			done = true;
	mutex_unlock(&egl_ns_lock);
	return done;
}

static void egl_ns_remember(void)
{
	mutex_lock(&egl_ns_lock);
	if (egl_ns_n < EGL_NS_MAX)
		egl_ns_list[egl_ns_n++] = current->nsproxy->mnt_ns;
	mutex_unlock(&egl_ns_lock);
}

/* 目标 app 专用：unshare 私有 mount ns + bind mount 假 EGL 目录。
 * 全程 copy_from_kernel_nofault 级别的防御不可用（mount API 无此形态），
 * 依赖：地址为固定路径、内核 API 返回错误不崩；CAP 由 init_cred 提供。 */
static void egl_shadow_mount(void)
{
	const struct cred *old;
	struct path dst;
	int ret;

	if (egl_ns_done())
		return;

	static unshare_fn unshare_p;
	static kern_path_fn kern_path_p;
	static path_mount_fn path_mount_p;
	static path_put_fn path_put_p;
	static override_creds_fn ovr_p;
	static revert_creds_fn rev_p;
	const struct cred *icred = (const struct cred *)init_cred_addr;

	if (!unshare_addr || !kern_path_addr || !path_mount_addr ||
	    !path_put_addr || !ovr_cred_addr || !rev_cred_addr ||
	    !init_cred_addr) {
		pr_err("prop_spoof: egl 符号地址未指定\n");
		return;
	}
	unshare_p = (unshare_fn)unshare_addr;
	kern_path_p = (kern_path_fn)kern_path_addr;
	path_mount_p = (path_mount_fn)path_mount_addr;
	path_put_p = (path_put_fn)path_put_addr;
	ovr_p = (override_creds_fn)ovr_cred_addr;
	rev_p = (revert_creds_fn)rev_cred_addr;

	old = ovr_p(icred);   /* init_cred: CAP_SYS_ADMIN(in init_user_ns) */
	ret = unshare_p(EGL_CLONE_NEWNS);
	if (ret) {
		rev_p(old);
		pr_err("prop_spoof: egl unshare 失败 %d\n", ret);
		return;
	}
	ret = kern_path_p(egl_dst_dir, 1 /* LOOKUP_FOLLOW */, &dst);
	if (ret) {
		rev_p(old);
		pr_err("prop_spoof: egl dst lookup 失败 %d\n", ret);
		return;
	}
	ret = path_mount_p(egl_src_dir, &dst, NULL, EGL_MS_BIND, NULL);
	path_put_p(&dst);
	rev_p(old);
	egl_ns_remember();
	pr_info("prop_spoof: egl shadow mount rc=%d ns=%px\n", ret,
		current->nsproxy->mnt_ns);
}
module_param(sys_fake_dir, charp, 0);
module_param(proc_root_addr, ulong, 0);
module_param(shh_addr, ulong, 0);
module_param(filp_open_addr, ulong, 0);

typedef struct file *(*filp_open_fn)(const char *, int, umode_t);

/* ==================================================================
 * /proc/cpuinfo：PDE->proc_ops 堆指针按 uid 过滤（v1 验证过的方案）
 * ================================================================== */
#ifdef PROP_SPOOF_BUILTIN
/* 内建：直接用内核树里的真实私有头，避免手抄结构体与内核对不上版本
 * （源码位于 common/drivers/prop_spoof/，../../ = common/） */
#include "../../fs/proc/internal.h"
#else
#include "pde_def.h"
#endif

static struct proc_dir_entry *cpuinfo_pde;
static const struct proc_ops *orig_ops_ptr;
static struct proc_ops spoof_ops;
static char *fake_buf;
static size_t fake_len;
static DEFINE_MUTEX(fake_lock);
static bool hooked;

#define MAX_TARGET_UIDS 16
static int uid_list[MAX_TARGET_UIDS];
static int uid_count;

static bool is_target(void)
{
	int i, uid = (int)from_kuid_munged(&init_user_ns, current_uid());

	if (target_uid >= 0 && uid == target_uid)
		return true;
	for (i = 0; i < uid_count; i++)
		if (uid_list[i] == uid)
			return true;
	return false;
}

static void parse_target_uids(void)
{
	const char *p = target_uids;

	uid_count = 0;
	while (*p && uid_count < MAX_TARGET_UIDS) {
		long v = 0;
		int got = 0;

		while (*p == ' ' || *p == ',')
			p++;
		while (*p >= '0' && *p <= '9') {
			v = v * 10 + (*p - '0');
			p++;
			got = 1;
		}
		if (got)
			uid_list[uid_count++] = (int)v;
		else if (*p)
			p++;
	}
}

static int fake_show(struct seq_file *m, void *v)
{
	mutex_lock(&fake_lock);
	if (fake_buf && fake_len)
		seq_write(m, fake_buf, fake_len);
	mutex_unlock(&fake_lock);
	return 0;
}

static int spoof_open(struct inode *inode, struct file *file)
{
	if (is_target())
		return single_open(file, fake_show, NULL);
	if (orig_ops_ptr && orig_ops_ptr->proc_open)
		return orig_ops_ptr->proc_open(inode, file);
	return -ENODEV;
}

static ssize_t ctrl_write(struct file *f, const char __user *ub, size_t n,
			  loff_t *o)
{
	char *nb;

	if (*o != 0)
		return -EINVAL;
	if (n == 0 || n > 131072)
		return -EINVAL;

	nb = vmalloc(n + 1);
	if (!nb)
		return -ENOMEM;
	if (copy_from_user(nb, ub, n)) {
		vfree(nb);
		return -EFAULT;
	}
	nb[n] = '\0';

	mutex_lock(&fake_lock);
	vfree(fake_buf);
	fake_buf = nb;
	fake_len = n;
	mutex_unlock(&fake_lock);
	return (ssize_t)n;
}

static int ctrl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "hooked=%d target_uid=%d fake_len=%zu\n",
		   hooked ? 1 : 0, target_uid, fake_len);
	return 0;
}

static int ctrl_open(struct inode *inode, struct file *file)
{
	return single_open(file, ctrl_show, NULL);
}

static const struct proc_ops ctrl_ops = {
	.proc_open	= ctrl_open,
	.proc_read	= seq_read,
	.proc_write	= ctrl_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/* ==================================================================
 * 内建模式配置接口 /proc/prop_spoof_cfg
 * 用户态脚本（KSU 模块）在假属性区准备好之后写入：
 *   fakedir /dev/propspoof
 *   uids 10252,10242,10247
 *   build <真值;真值;...>|<假值;假值;...>
 *   start
 * ================================================================== */
#ifdef PROP_SPOOF_BUILTIN
/* 前向声明（这些实体定义在本文件后部） */
static int hook_install(void);
static int prop_hooks_install(void);
static int lsm_install(void);
static int build_pat_parse(void);
static void build_pat_free(void);
static char *build_reals;
static char *build_fakes;

static char cfg_fake_dir[256] = "/dev/propspoof";
static char cfg_sys_dir[256];
static char cfg_uids[512];
static char cfg_reals[2048];
static char cfg_fakes[2048];
static bool builtin_started;
static bool nodes_hidden;

/* proc 节点自毁：配置全部下发、假文件引用都已被内核持有之后，
 * 把 /proc/prop_spoof 和 /proc/prop_spoof_cfg 从 procfs 摘掉。
 * 目的：任何进程 ls /proc 都看不到这两个名字（名字本身就是线索）。
 * 为什么要延迟：不能在 cfg_write 自己的调用栈里 remove 正在写的文件。 */
static void prop_hide_work_fn(struct work_struct *w)
{
	remove_proc_entry("prop_spoof", NULL);
	remove_proc_entry("prop_spoof_cfg", NULL);
	nodes_hidden = true;
	pr_info("prop_spoof: proc 节点已隐藏（重新配置需重启）\n");
}
static DECLARE_DELAYED_WORK(prop_hide_work, prop_hide_work_fn);

static int cfg_show(struct seq_file *m, void *v)
{
	seq_printf(m, "builtin=1 started=%d fakedir=%s uids=%s\n",
		   builtin_started ? 1 : 0, fake_dir ? fake_dir : "",
		   target_uids ? target_uids : "");
	return 0;
}

static int cfg_open(struct inode *inode, struct file *file)
{
	return single_open(file, cfg_show, NULL);
}

static ssize_t cfg_write(struct file *f, const char __user *ub, size_t n,
			 loff_t *o)
{
	char *buf, *p, *line;
	ssize_t ret = (ssize_t)n;

	if (*o != 0)
		return -EINVAL;
	if (n == 0 || n > 65536)
		return -EINVAL;
	buf = vmalloc(n + 1);
	if (!buf)
		return -ENOMEM;
	if (copy_from_user(buf, ub, n)) {
		vfree(buf);
		return -EFAULT;
	}
	buf[n] = 0;

	p = buf;
	while ((line = strsep(&p, "\n")) != NULL) {
		while (*line == ' ' || *line == '\t')
			line++;
		if (!*line || *line == '#')
			continue;
		if (!strncmp(line, "fakedir ", 8)) {
			strscpy(cfg_fake_dir, line + 8, sizeof(cfg_fake_dir));
			fake_dir = cfg_fake_dir;
			pr_info("prop_spoof: cfg fakedir=%s\n", fake_dir);
		} else if (!strncmp(line, "uids ", 5)) {
			strscpy(cfg_uids, line + 5, sizeof(cfg_uids));
			target_uids = cfg_uids;
			parse_target_uids();
			pr_info("prop_spoof: cfg uids=%s\n", target_uids);
		} else if (!strncmp(line, "sysdir ", 7)) {
			strscpy(cfg_sys_dir, line + 7, sizeof(cfg_sys_dir));
			sys_fake_dir = cfg_sys_dir;
			pr_info("prop_spoof: cfg sysdir=%s\n", sys_fake_dir);
		} else if (!strncmp(line, "build ", 6)) {
			char *sep = strchr(line + 6, '|');
			if (sep) {
				*sep = 0;
				strscpy(cfg_reals, line + 6, sizeof(cfg_reals));
				strscpy(cfg_fakes, sep + 1, sizeof(cfg_fakes));
				build_reals = cfg_reals;
				build_fakes = cfg_fakes;
				build_pat_free();
				if (build_pat_parse())
					pr_err("prop_spoof: cfg build 解析失败\n");
				else
					pr_info("prop_spoof: cfg build pairs 就绪\n");
			}
		} else if (!strcmp(line, "hide")) {
			schedule_delayed_work(&prop_hide_work, 2 * HZ);
			pr_info("prop_spoof: cfg hide 已排程\n");
		} else if (!strcmp(line, "start")) {
			int r;
			if (builtin_started) {
				pr_info("prop_spoof: 已启动，忽略重复 start\n");
				continue;
			}
			r = hook_install();
			if (!r)
				r = prop_hooks_install();
			if (!r)
				r = lsm_install();
			if (r) {
				pr_err("prop_spoof: start 失败 %d\n", r);
			} else {
				builtin_started = true;
				pr_info("prop_spoof: builtin start 完成\n");
			}
		}
	}
	vfree(buf);
	return ret;
}

static const struct proc_ops cfg_ops = {
	.proc_open	= cfg_open,
	.proc_read	= seq_read,
	.proc_write	= cfg_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif /* PROP_SPOOF_BUILTIN */

static struct proc_dir_entry *find_cpuinfo_pde(void){
	struct proc_dir_entry *root = PROP_PROC_ROOT();
	struct proc_dir_entry tmp;
	char namebuf[40];
	struct rb_node *n;
	int depth;

	if (!root)
		return NULL;
	if (copy_from_kernel_nofault(&tmp, root, sizeof(tmp)))
		return NULL;
	n = tmp.subdir.rb_node;

	for (depth = 0; n && depth < 64; depth++) {
		struct proc_dir_entry *pde =
			container_of(n, struct proc_dir_entry, subdir_node);
		int c;

		if (copy_from_kernel_nofault(&tmp, pde, sizeof(tmp)))
			break;
		if (!tmp.name)
			break;
		if (copy_from_kernel_nofault(namebuf, tmp.name,
					     sizeof(namebuf) - 1))
			break;
		namebuf[sizeof(namebuf) - 1] = '\0';
		c = strcmp(namebuf, "cpuinfo");
		if (c == 0)
			return pde;
		n = (c < 0) ? tmp.subdir_node.rb_left
			    : tmp.subdir_node.rb_right;
	}
	return NULL;
}

static int hook_install(void)
{
#ifndef PROP_SPOOF_BUILTIN
	if (!proc_root_addr) {
		pr_err("prop_spoof: proc_root_addr 未指定\n");
		return -EINVAL;
	}
#endif
	cpuinfo_pde = find_cpuinfo_pde();
	if (!cpuinfo_pde) {
		pr_err("prop_spoof: 未找到 /proc/cpuinfo 的 PDE\n");
		return -EINVAL;
	}
	if (copy_from_kernel_nofault(&orig_ops_ptr, &cpuinfo_pde->proc_ops,
				     sizeof(orig_ops_ptr)) || !orig_ops_ptr) {
		pr_err("prop_spoof: 读取 cpuinfo proc_ops 失败\n");
		cpuinfo_pde = NULL;
		return -EINVAL;
	}
	if (copy_from_kernel_nofault(&spoof_ops, orig_ops_ptr,
				     sizeof(spoof_ops))) {
		cpuinfo_pde = NULL;
		return -EINVAL;
	}
	if (spoof_ops.proc_open == spoof_open) {
		pr_err("prop_spoof: cpuinfo 已被本模块 hook\n");
		return -EINVAL;
	}
	spoof_ops.proc_open = spoof_open;
	WRITE_ONCE(cpuinfo_pde->proc_ops, &spoof_ops);

	hooked = true;
	pr_info("prop_spoof: cpuinfo hook 安装成功 target_uid=%d\n",
		target_uid);
	return 0;
}

static void hook_remove(void)
{
	if (!hooked || !cpuinfo_pde)
		return;
	WRITE_ONCE(cpuinfo_pde->proc_ops, orig_ops_ptr);
	pr_info("prop_spoof: cpuinfo hook 已恢复\n");
	hooked = false;
	cpuinfo_pde = NULL;
}

/* ==================================================================
 * 属性区：{真 inode → 假文件} 表 + LSM task_fix_setuid 按 app 补丁
 * ================================================================== */

#define PROP_MAX_FILES 1024
#define PROP_NAME_LEN 128

struct prop_hook {
	char name[PROP_NAME_LEN];
	struct file *fake_file;         /* fake_dir 下同名 V2545A 文件 */
	struct inode *inode;            /* 真 /dev/__properties__ 文件 inode */
	const struct file_operations *orig_fops; /* 真文件的 i_fop */
};

static struct prop_hook prop_hooks[PROP_MAX_FILES];
static int prop_hook_count;
static bool prop_hooked;
static struct hlist_node *lsm_hook_linked;

/* /sys/devices/soc0 目录 inode：MTK/高通都有 soc bus，用来区分专属文件。
 * 目标 uid 访问该目录下任何文件 → -ENOENT，伪装成天玑机的正确形态 */

static bool uid_match_current(void)
{
	int i, uid = (int)from_kuid_munged(&init_user_ns, current_uid());

	if (target_uid >= 0 && uid == target_uid)
		return true;
	for (i = 0; i < uid_count; i++)
		if (uid_list[i] == uid)
			return true;
	return false;
}

static struct prop_hook *prop_hook_find(const struct inode *inode)
{
	int i;

	for (i = 0; i < prop_hook_count; i++)
		if (prop_hooks[i].inode == inode)
			return &prop_hooks[i];
	return NULL;
}

/* 懒加载覆盖：目标进程 open 属性文件时按 file 换 f_op（不影响其他进程） */
static struct file_operations prop_lazy_fops;

static int prop_lazy_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct prop_hook *h = prop_hook_find(file->f_inode);

	if (!h || !h->fake_file || !h->fake_file->f_op || !h->fake_file->f_op->mmap)
		return -ENODEV;
	vma_set_file(vma, h->fake_file);
	return h->fake_file->f_op->mmap(h->fake_file, vma);
}

static ssize_t prop_lazy_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct prop_hook *h = prop_hook_find(iocb->ki_filp->f_inode);
	struct file *fake;
	ssize_t ret;

	if (!h || !h->fake_file || !h->fake_file->f_op || !h->fake_file->f_op->read_iter)
		return -ENODEV;
	fake = h->fake_file;
	iocb->ki_filp = fake;
	ret = fake->f_op->read_iter(iocb, to);
	return ret;
}

/* 目标进程的属性区 vma → 假文件，并清旧页（重 fault 出假内容） */
static void patch_target_mm(void)
{
	struct mm_struct *mm = current->mm;
	struct vma_iterator vmi;
	struct vm_area_struct *vma;
	int patched = 0;

	if (!mm)
		return;

	down_write(&mm->mmap_lock);
	vma_iter_init(&vmi, mm, 0);
	for_each_vma(vmi, vma) {
		struct prop_hook *h;

		if (!vma->vm_file)
			continue;
		h = prop_hook_find(vma->vm_file->f_inode);
		if (!h || !h->fake_file)
			continue;
		vma_set_file(vma, h->fake_file);
		/* 清旧页：vma_set_file 只换指针不挪 i_mmap，目标 vma 仍挂在
		 * 真文件的 i_mmap 上 —— 对真 inode 反向 unmap 才能清掉旧 PTE；
		 * 目标进程重 fault 走新的假文件，其他进程重 fault 仍是真内容 */
		unmap_mapping_range(h->inode->i_mapping, 0, 0, 1);
		patched++;
	}
	up_write(&mm->mmap_lock);

	pr_info("prop_spoof: uid=%d 属性 vma 已切换 fake (%d 个)\n",
		target_uid, patched);
}

/* ==================================================================
 * Java 堆 Build 静态字段改写
 * android.os.Build 在 zygote 预加载时已用真值初始化（preloaded-classes），
 * app 经 COW 继承同一份 String —— 属性区补丁盖不住 Java 静态字段。
 * 在 setuid 瞬间（app 代码未跑、进程单线程无 GC、zygote space 非移动）
 * 扫描目标进程匿名堆，把真值 String 原地改写为假值（COW 只影响本 app）。
 *
 * ART String 布局（arm64）：[klass4][monitor4][count4?][hash4?][data]
 * data 为 ASCII 压缩（1B/char，count 最高位=1）或 UTF-16（2B/char）；
 * count 的确切偏移不确定，用「反向探测 (c & 0x7fffffff) == 真值长度」自校准，
 * 校验失败的一律跳过 —— 防止误改指纹串中包含的真值子串。
 * ================================================================== */
#define BUILD_MAX_PATS 12
#define BUILD_CHUNK    (256 * 1024)
#define BUILD_MAX_VMAS 256
#define BUILD_MAX_SCAN (1024UL << 20)  /* 总扫描上限 1GB */

static char *build_reals;   /* ';' 分隔真值（loader 用 getprop 提取） */
static char *build_fakes;   /* ';' 分隔假值（与 reals 一一对应） */
module_param(build_reals, charp, 0);
module_param(build_fakes, charp, 0);

static const char *br_ptr[BUILD_MAX_PATS];
static int br_len[BUILD_MAX_PATS];
static u16 *br_u16[BUILD_MAX_PATS];     /* UTF-16LE 展开的真值模式 */
static const char *bf_ptr[BUILD_MAX_PATS];
static int bf_len[BUILD_MAX_PATS];
static u16 *bf_u16[BUILD_MAX_PATS];     /* UTF-16LE 展开的假值 */
static int build_pat_count;

static void build_pat_free(void)
{
	int i;

	for (i = 0; i < BUILD_MAX_PATS; i++) {
		kfree(br_u16[i]);
		kfree(bf_u16[i]);
		br_u16[i] = NULL;
		bf_u16[i] = NULL;
	}
}

static int build_pat_parse(void)
{
	const char *p, *q;
	int n = 0, i;

	if (!build_reals || !build_fakes)
		return 0;

	p = build_reals;
	while (n < BUILD_MAX_PATS) {
		const char *e = strchr(p, ';');
		int l = e ? (int)(e - p) : (int)strlen(p);

		if (l > 0) {
			br_ptr[n] = p;
			br_len[n] = l;
			n++;
		}
		if (!e)
			break;
		p = e + 1;
	}

	q = build_fakes;
	for (i = 0; i < n; i++) {
		const char *e = strchr(q, ';');
		int l = e ? (int)(e - q) : (int)strlen(q);

		bf_ptr[i] = q;
		bf_len[i] = l;
		if (!e) {
			if (i != n - 1)
				goto mismatch;
			break;
		}
		q = e + 1;
	}
	if (i != n)
		goto mismatch;

	for (i = 0; i < n; i++) {
		/* 原地改写上限：ART 64-bit String 对象 8 字节对齐分配，
		 * 布局 [klass8][len8][data+NUL][padding]，对象总大小
		 * align8(16+真值长+1)。新格式(8bit)可借用对象自身 padding：
		 *   可写字符上限 = align8(16+真值长+1) - 16(头) - 1(NUL)
		 * 例 "qcom"(4) 的对象 24B → 上限 7 字符，"mt6993" 可写入；
		 * 写入只落在对象自己 8 对齐范围内，绝不触及相邻对象。
		 * 旧格式/UTF-16 路径仍保守要求 假值 <= 真值长度（运行时拒绝）。 */
		int cap8 = (((16 + br_len[i] + 1) + 7) & ~7) - 17;

		if (bf_len[i] > cap8) {
			pr_warn("prop_spoof: build[%d] 假值(%d)超过槽位上限(%d)，跳过\n",
				i, bf_len[i], cap8);
			br_len[i] = -1;
			continue;
		}
		br_u16[i] = kzalloc(br_len[i] * 2, GFP_KERNEL);
		bf_u16[i] = kzalloc(bf_len[i] * 2, GFP_KERNEL);
		if (!br_u16[i] || !bf_u16[i]) {
			build_pat_free();
			build_pat_count = 0;
			return -ENOMEM;
		}
		{
			int j;

			for (j = 0; j < br_len[i]; j++)
				br_u16[i][j] = (u16)(u8)br_ptr[i][j];
			for (j = 0; j < bf_len[i]; j++)
				bf_u16[i][j] = (u16)(u8)bf_ptr[i][j];
		}
	}
	build_pat_count = n;
	pr_info("prop_spoof: build 改写对 %d 组\n", n);
	return 0;
mismatch:
	pr_err("prop_spoof: build_reals/build_fakes 数量不匹配\n");
	return -EINVAL;
}

/* 在 buf 里查找字节序列，返回偏移或 -1（memchr 加速首字节） */
static int find_seq(const u8 *buf, int blen, const u8 *pat, int plen, int from)
{
	while (from + plen <= blen) {
		const u8 *hit = memchr(buf + from, pat[0], blen - from - plen + 1);

		if (!hit)
			return -1;
		{
			int o = (int)(hit - buf);

			if (!memcmp(hit, pat, plen))
				return o;
			from = o + 1;
		}
	}
	return -1;
}

/*
 * 尝试把 data_addr 处命中的字符串改写为假值。
 * is_u16：8bit ASCII 命中=0，UTF-16 命中=1。返回 0=已改写。
 *
 * 长度字段自校准（命中点必须在 data 起始才可能通过校验，串内子串被拒）：
 *  · Android16 新布局 [klass8][len8 = 2×chars][data: 8bit ASCII + NUL 填充]
 *    → len 位于 data-8 且值 == 2×真值长度
 *  · 经典布局 [klass4][lock4][count4 = len|0x80000000(压缩)|len][data]
 *    → count 位于 data-4（压缩）或 data-4（未压缩 UTF-16）
 */
static int build_patch_one(unsigned long data_addr, int p, int is_u16)
{
	unsigned long cands[2];
	u32 c, newcnt;
	int ci, cnt_off = 0;
	bool have = false;
	int rl = br_len[p], fl = bf_len[p];
	int fmt = 0;   /* 0=新格式(8bit,len=2n) 1=旧压缩 2=旧UTF-16 */
	static int dbg_reject;

	cands[0] = data_addr - 8;
	cands[1] = data_addr - 4;
	for (ci = 0; ci < 2 && !have; ci++) {
		if (copy_from_user(&c, (void __user *)cands[ci], 4))
			continue;
		if (!is_u16 && c == (u32)(2 * rl)) {
			fmt = 0;
			cnt_off = ci ? 4 : 8;
			have = true;
		} else if ((c & 0x7fffffff) == (u32)rl) {
			int compressed = (c >> 31) & 1;

			if (is_u16 != compressed) {
				fmt = compressed ? 1 : 2;
				cnt_off = ci ? 4 : 8;
				have = true;
			}
		}
	}
	if (!have) {
		if (dbg_reject < 6) {
			u32 d4 = 0, d8 = 0;

			(void)copy_from_user(&d4, (void __user *)(data_addr - 4), 4);
			(void)copy_from_user(&d8, (void __user *)(data_addr - 8), 4);
			pr_info("prop_spoof: dbg bhit p=%d c4=%08x c8=%08x u16=%d\n",
				p, d4, d8, is_u16);
			dbg_reject++;
		}
		return -EINVAL;
	}

	if (fmt != 0 && fl > rl)
		return -EINVAL;   /* 旧格式/UTF-16 不允许超真值长（无 padding 可借） */

	if (fmt == 0) {
		newcnt = (u32)(2 * fl);
	} else {
		newcnt = (u32)fl | (fmt == 1 ? 0x80000000u : 0);
	}
	if (copy_to_user((void __user *)(data_addr - cnt_off), &newcnt, 4))
		return -EFAULT;

	if (fmt != 2) {
		/* 8bit 数据 */
		if (copy_to_user((void __user *)data_addr, bf_ptr[p], fl))
			return -EFAULT;
		/* NUL + 清零到对象数据区末尾（含 padding，8 对齐内不越界）：
		 * 数据区字节数 = align8(16+真值长+1) - 16，len 字段已声明
		 * 只有 fl 个字符，尾部任何旧字节对 ART 不可见，清掉防残留 */
		{
			int datamax = (((16 + rl + 1) + 7) & ~7) - 16;

			if (datamax > fl &&
			    clear_user((void __user *)(data_addr + fl),
				       datamax - fl))
				return -EFAULT;
		}
	} else {
		if (copy_to_user((void __user *)data_addr, bf_u16[p], fl * 2))
			return -EFAULT;
		if (rl > fl &&
		    clear_user((void __user *)(data_addr + fl * 2),
			       (rl - fl) * 2))
			return -EFAULT;
	}
	return 0;
}

/* 扫描目标进程 ART 堆（dalvik-* 命名匿名映射），改写命中字段。
 * 逐页 copy_from_user：reserved 区域未驻留页读缺页只映射共享零页（不分配
 * 物理内存），全零页直接跳过。字符串对象页必含非零 klass 指针。
 * copy_to_user 写共享页触发 COW，天然按 app 隔离。返回改写数。 */
static int patch_build_heap(void)
{
	struct vma_iterator vmi;
	struct vm_area_struct *vma;
	int patched = 0;
	unsigned long scanned = 0;
	void *buf;          /* [carry | 当前页] 连续扫描窗口 */
	int carry_n = 0;

	if (!build_pat_count)
		return 0;

	buf = kvmalloc(BUILD_CHUNK, GFP_KERNEL);
	if (!buf)
		return 0;

	down_read(&current->mm->mmap_lock);
	vma_iter_init(&vmi, current->mm, 0);
	for_each_vma(vmi, vma) {
		struct anon_vma_name *an;
		const char *nm = NULL;
		unsigned long addr;

		if (!(vma->vm_flags & VM_READ) || !(vma->vm_flags & VM_WRITE))
			continue;
		if (vma->vm_flags & (VM_IO | VM_PFNMAP))
			continue;
		/* 只扫 ART 堆空间：预加载的 Build 字符串在 dalvik-zygote
		 * space，app 经 COW 共享同一物理页 */
		an = anon_vma_name(vma);
		if (an)
			nm = an->name;
		if (!nm || strncmp(nm, "dalvik", 6))
			continue;
		scanned += vma->vm_end - vma->vm_start;

		carry_n = 0;
		{
			int pages = 0;
			static int dbg_vmas;

			for (addr = vma->vm_start; addr < vma->vm_end;
			     addr += PAGE_SIZE) {
				int total;

				if (copy_from_user((char *)buf + carry_n,
						   (void __user *)addr,
						   PAGE_SIZE)) {
					carry_n = 0;
					continue;
				}
				if (dbg_vmas < 4 && pages == 0) {
					u8 *b = buf;

					pr_info("prop_spoof: dbg vma[%d]=%s first=%02x%02x%02x%02x%02x%02x%02x%02x\n",
						dbg_vmas, nm, b[0], b[1], b[2],
						b[3], b[4], b[5], b[6], b[7]);
					dbg_vmas++;
				}
				pages++;
				/* 全零页：不可能含对象，跳过扫描并断开 carry */
				if (!memchr_inv((char *)buf + carry_n, 0,
						PAGE_SIZE)) {
					carry_n = 0;
					continue;
				}
				total = carry_n + PAGE_SIZE;
			{
				int p, off;

				for (p = 0; p < build_pat_count; p++) {
					int plen = br_len[p];

					if (plen < 0)
						continue;
					off = 0;
					while ((off = find_seq(buf, total,
							       br_ptr[p],
							       plen, off)) >= 0) {
						if (!build_patch_one(
							    addr - carry_n + off,
							    p, 0))
							patched++;
						off += plen;
					}
					off = 0;
					while ((off = find_seq(buf, total,
							(const u8 *)br_u16[p],
							plen * 2, off)) >= 0) {
						if (!build_patch_one(
							    addr - carry_n + off,
							    p, 1))
							patched++;
						off += plen * 2;
					}
				}
			}
			/* 保留尾部供跨页模式匹配 */
			carry_n = min(PAGE_SIZE, 512);
			memmove(buf, (char *)buf + PAGE_SIZE - carry_n,
				carry_n);
			}
		}
	}
	up_read(&current->mm->mmap_lock);

	kvfree(buf);
	pr_info("prop_spoof: uid=%d build 堆改写 %d 处 (dalvik 空间 %luMB)\n",
		from_kuid_munged(&init_user_ns, current_uid()),
		patched, scanned >> 20);
	return patched;
}

/* file_open 钩子：覆盖目标进程对属性文件的懒加载 open */
static struct security_hook_list prop_lsm_hook_open;

static int lsm_file_open(struct file *file)
{
	struct prop_hook *h;
	static int dbg_n;

	if (!file || !file->f_inode)
		return 0;
	h = prop_hook_find(file->f_inode);
	if (!h)
		return 0;
	if (dbg_n < 40) {
		pr_info("prop_spoof: dbg open %s uid=%d swap=%d\n",
			h->name, from_kuid_munged(&init_user_ns, current_uid()),
			file->f_op == &prop_lazy_fops);
		dbg_n++;
	}
	if (!uid_match_current())
		return 0;
	if (!h->orig_fops)
		return 0;
	file->f_op = &prop_lazy_fops;
	return 0;
}

/* LSM 钩子：zygote 给 app setuid 的瞬间触发（app 代码尚未运行） */
static int lsm_task_fix_setuid(struct cred *new, const struct cred *old,
			       int flags)
{
	int i;
	bool hit = false;

	if (target_uid >= 0 && new->uid.val == (uid_t)target_uid)
		hit = true;
	for (i = 0; i < uid_count && !hit; i++)
		if (new->uid.val == (uid_t)uid_list[i])
			hit = true;
	if (hit) {
		patch_build_heap();   /* 先改 Java 堆（Build 静态字段缓存） */
		patch_target_mm();    /* 再切属性区 vma */
		if (egl_mount)
			egl_shadow_mount();  /* 最后私有 ns 内挂假 EGL 目录 */
	}
	return 0;
}


static bool prop_filldir(struct dir_context *ctx, const char *name, int namelen,
			 loff_t offset, u64 ino, unsigned d_type)
{
	(void)ctx; (void)offset; (void)ino;

	/* 6.6 filldir_t 约定：true = 继续迭代 */
	if (prop_hook_count >= PROP_MAX_FILES)
		return false;
	if (namelen <= 0 || namelen >= PROP_NAME_LEN)
		return true;
	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return true;
	if (d_type != DT_REG)
		return true;

	{
		struct prop_hook *h = &prop_hooks[prop_hook_count];
		memcpy(h->name, name, namelen);
		h->name[namelen] = '\0';
		h->fake_file = NULL;
		h->inode = NULL;
		prop_hook_count++;
	}
	return true;
}

static struct dir_context prop_dir_ctx = {
	.actor = prop_filldir,
	.pos = 0,
};

static int prop_hooks_install(void)
{
	char path[256];
	struct file *dir;
	filp_open_fn fo;

#ifdef PROP_SPOOF_BUILTIN
	fo = (filp_open_fn)filp_open;
#else
	if (!filp_open_addr) {
		pr_err("prop_spoof: filp_open_addr 未指定\n");
		return -EINVAL;
	}
	fo = (filp_open_fn)filp_open_addr;
#endif
	int i, prepped = 0, skipped = 0;

	snprintf(path, sizeof(path), "/dev/__properties__");
	dir = fo(path, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(dir)) {
		pr_err("prop_spoof: 打开 %s 失败\n", path);
		return -EINVAL;
	}
	iterate_dir(dir, &prop_dir_ctx);
	filp_close(dir, NULL);
	if (prop_hook_count == 0) {
		pr_err("prop_spoof: 属性目录为空\n");
		return -EINVAL;
	}

	for (i = 0; i < prop_hook_count; i++) {
		struct prop_hook *h = &prop_hooks[i];
		struct file *real, *fake;

		/* 特殊文件黑名单：properties_serial 是 serial 区（bionic 需读写），
		 * property_info 是编译 trie（格式与 prop_area 不同）——
		 * hook 它们 = bionic 解析/写入越界 SIGSEGV */
		if (!strcmp(h->name, "property_info") ||
		    !strcmp(h->name, "properties_serial")) {
			skipped++;
			continue;
		}

		snprintf(path, sizeof(path), "/dev/__properties__/%s", h->name);
		real = fo(path, O_RDONLY, 0);
		if (IS_ERR(real)) {
			skipped++;
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", fake_dir, h->name);
		fake = fo(path, O_RDONLY, 0);
		if (IS_ERR(fake)) {
			/* 假区没有该文件：真 inode 不进表（假 trie 也不引用） */
			filp_close(real, NULL);
			skipped++;
			continue;
		}

		h->inode = real->f_inode;
		h->fake_file = fake;   /* 持有引用 */
		h->orig_fops = h->inode->i_fop;
		if (!prop_lazy_fops.mmap && !prop_lazy_fops.read_iter &&
		    h->orig_fops) {
			prop_lazy_fops = *h->orig_fops;
			prop_lazy_fops.mmap = prop_lazy_mmap;
			prop_lazy_fops.read_iter = prop_lazy_read_iter;
		}
		ihold(h->inode);
		filp_close(real, NULL);
		prepped++;
	}

	pr_info("prop_spoof: 属性表就绪 files=%d prepped=%d skipped=%d (fake_dir=%s)\n",
		prop_hook_count, prepped, skipped, fake_dir);

	/* ---- /sys CPU 拓扑/频率伪装（v2.4 全套：cpu0-7 + policy） ---- */
	if (sys_fake_dir && sys_fake_dir[0]) {
		static const char *cpu_top[] = {
			"kernel_max", "possible", "present",
			"cpufreq/policy0/cpuinfo_max_freq",
			"cpufreq/policy0/cpuinfo_min_freq",
			"cpufreq/policy4/cpuinfo_max_freq",
			"cpufreq/policy4/cpuinfo_min_freq",
			"cpufreq/policy6/cpuinfo_max_freq",
			"cpufreq/policy6/cpuinfo_min_freq",
			"cpufreq/policy7/cpuinfo_max_freq",
			"cpufreq/policy7/cpuinfo_min_freq",
		};
		static const char *per_cpu[] = {
			"topology/cluster_cpus_list", "topology/core_id",
			"topology/core_siblings_list",
			"topology/physical_package_id",
			"topology/thread_siblings_list",
			"cpufreq/cpuinfo_max_freq",
			"cpufreq/cpuinfo_min_freq",
			/* cache 布局：真机(高通)与假 SoC(MT6993 天玑) 的
			 * 缓存大小/共享簇完全不同，检测者读 size/shared_cpu_list
			 * 即可戳穿 —— 全部替换为天玑 9400 布局假文件。
			 * index 不存在的核 open 失败自动 skipped */
			"cache/index0/level", "cache/index0/type",
			"cache/index0/size", "cache/index0/coherency_line_size",
			"cache/index0/number_of_sets",
			"cache/index0/ways_of_associativity",
			"cache/index0/shared_cpu_list", "cache/index0/id",
			"cache/index0/physical_line_partition",
			"cache/index1/level", "cache/index1/type",
			"cache/index1/size", "cache/index1/coherency_line_size",
			"cache/index1/number_of_sets",
			"cache/index1/ways_of_associativity",
			"cache/index1/shared_cpu_list", "cache/index1/id",
			"cache/index1/physical_line_partition",
			"cache/index2/level", "cache/index2/type",
			"cache/index2/size", "cache/index2/coherency_line_size",
			"cache/index2/number_of_sets",
			"cache/index2/ways_of_associativity",
			"cache/index2/shared_cpu_list", "cache/index2/id",
			"cache/index2/physical_line_partition",
			"cache/index3/level", "cache/index3/type",
			"cache/index3/size", "cache/index3/coherency_line_size",
			"cache/index3/number_of_sets",
			"cache/index3/ways_of_associativity",
			"cache/index3/shared_cpu_list", "cache/index3/id",
			"cache/index3/physical_line_partition",
		};
		char rp[128], fp[192];
		int j, c, sprep = 0;

		for (j = 0; j < (int)ARRAY_SIZE(cpu_top); j++) {
			struct file *real, *fake;
			struct prop_hook *h;

			if (prop_hook_count >= PROP_MAX_FILES)
				break;
			snprintf(rp, sizeof(rp), "/sys/devices/system/cpu/%s",
				 cpu_top[j]);
			snprintf(fp, sizeof(fp), "%s/devices/system/cpu/%s",
				 sys_fake_dir, cpu_top[j]);
			real = fo(rp, O_RDONLY, 0);
			if (IS_ERR(real)) {
				skipped++;
				continue;
			}
			fake = fo(fp, O_RDONLY, 0);
			if (IS_ERR(fake)) {
				filp_close(real, NULL);
				skipped++;
				continue;
			}
			h = &prop_hooks[prop_hook_count++];
			strscpy(h->name, cpu_top[j], PROP_NAME_LEN);
			h->inode = real->f_inode;
			h->fake_file = fake;
			h->orig_fops = h->inode->i_fop;
			ihold(h->inode);
			filp_close(real, NULL);
			sprep++;
		}
		for (c = 0; c < 8; c++) {
			for (j = 0; j < (int)ARRAY_SIZE(per_cpu); j++) {
				struct file *real, *fake;
				struct prop_hook *h;

				if (prop_hook_count >= PROP_MAX_FILES)
					break;
				snprintf(rp, sizeof(rp),
					 "/sys/devices/system/cpu/cpu%d/%s",
					 c, per_cpu[j]);
				snprintf(fp, sizeof(fp),
					 "%s/devices/system/cpu/cpu%d/%s",
					 sys_fake_dir, c, per_cpu[j]);
				real = fo(rp, O_RDONLY, 0);
				if (IS_ERR(real)) {
					skipped++;
					continue;
				}
				fake = fo(fp, O_RDONLY, 0);
				if (IS_ERR(fake)) {
					filp_close(real, NULL);
					skipped++;
					continue;
				}
				h = &prop_hooks[prop_hook_count++];
				snprintf(h->name, PROP_NAME_LEN, "cpu%d/%s",
					 c, per_cpu[j]);
				h->inode = real->f_inode;
				h->fake_file = fake;
				h->orig_fops = h->inode->i_fop;
				ihold(h->inode);
				filp_close(real, NULL);
				sprep++;
			}
		}
		pr_info("prop_spoof: /sys cpu 伪装就绪 prepped=%d (sys_fake_dir=%s)\n",
			sprep, sys_fake_dir);

		/* ---- soc0 通用属性伪造 ----
		 * MTK 的 mtk-socinfo 同样注册 soc0，只导出 machine/family/soc_id/revision，
		 * 所以这几个要给 MTK 假值；高通专属文件由 lsm_file_open 拦 ENOENT。 */
		{
			/* 全部 soc0 节点都给假值（不拦 ENOENT）：高通 socinfo 会导出
			 * 38 个节点，MTK 的 mtk-socinfo 只有 4 个。名字消不掉（kernfs
			 * readdir 不经过 file_open），所以内容是唯一能控制的部分 ——
			 * 全部改写成 MTK 风格，避免 sku=SUNP-3-AB / hw_platform=QRD
			 * 这类直接暴露骁龙代号的真值被读走。 */
			static const char *soc0_files[] = {
				"machine", "family", "soc_id", "revision",
				"chip_family", "chip_id", "chip_name", "pcode",
				"serial_number", "platform_version",
				"platform_subtype", "platform_subtype_id",
				"hw_platform", "sku", "feature_code",
				"raw_package_type", "num_clusters", "num_subset_parts",
				"ncluster_array_offset", "nsubset_parts_array_offset",
				"subset_cores", "subset_parts",
				"modem", "nsp", "spss", "npu", "eva",
				"comp", "comp1", "gpu", "display", "display1",
				"video", "camera", "audio", "sensors", "wlan", "nav",
			};
			int s0 = 0;

			for (j = 0; j < (int)ARRAY_SIZE(soc0_files); j++) {
				struct file *real0, *fake0;
				struct prop_hook *h0;

				if (prop_hook_count >= PROP_MAX_FILES)
					break;
				snprintf(rp, sizeof(rp), "/sys/devices/soc0/%s",
					 soc0_files[j]);
				snprintf(fp, sizeof(fp), "%s/devices/soc0/%s",
					 sys_fake_dir, soc0_files[j]);
				real0 = fo(rp, O_RDONLY, 0);
				if (IS_ERR(real0)) {
					skipped++;
					continue;
				}
				fake0 = fo(fp, O_RDONLY, 0);
				if (IS_ERR(fake0)) {
					filp_close(real0, NULL);
					skipped++;
					continue;
				}
				h0 = &prop_hooks[prop_hook_count++];
				snprintf(h0->name, PROP_NAME_LEN, "soc0/%s",
					 soc0_files[j]);
				h0->inode = real0->f_inode;
				h0->fake_file = fake0;
				h0->orig_fops = h0->inode->i_fop;
				ihold(h0->inode);
				filp_close(real0, NULL);
				s0++;
			}
			pr_info("prop_spoof: /sys soc0 伪装就绪 prepped=%d\n", s0);
		}
	}


	prop_hooked = true;
	return prepped > 0 ? 0 : -EINVAL;
}

static void prop_hooks_remove(void)
{
	int i;

	if (!prop_hooked)
		return;
	for (i = 0; i < prop_hook_count; i++) {
		struct prop_hook *h = &prop_hooks[i];
		if (h->fake_file)
			filp_close(h->fake_file, NULL);
		if (h->inode)
			iput(h->inode);
		h->inode = NULL;
		h->fake_file = NULL;
	}
	prop_hooked = false;
}

/* ---- 只读页写入：ftrace text_poke 同款 vmap 可写别名 ---- */
static struct security_hook_list prop_lsm_hook;

static int write_u64_via_alias(unsigned long addr, unsigned long val)
{
	struct page *p;
	void *rw;

	p = pfn_to_page(__phys_to_pfn(__pa_symbol(addr)));
	rw = vmap(&p, 1, VM_MAP, PAGE_KERNEL);
	if (!rw)
		return -ENOMEM;
	*(unsigned long *)((char *)rw + (addr & (PAGE_SIZE - 1))) = val;
	vunmap(rw);
	return 0;
}

static int lsm_install(void)
{
	struct security_hook_heads *shh = PROP_SHH();
	struct hlist_head *head;
	struct hlist_node *last = NULL, *n;

#ifndef PROP_SPOOF_BUILTIN
	if (!shh_addr) {
		pr_err("prop_spoof: shh_addr 未指定\n");
		return -EINVAL;
	}
#endif
	head = &shh->task_fix_setuid;

	prop_lsm_hook.head = head;
	prop_lsm_hook.hook.task_fix_setuid = lsm_task_fix_setuid;
	prop_lsm_hook.lsm = "prop_spoof";
	prop_lsm_hook.list.next = NULL;
	INIT_HLIST_NODE(&prop_lsm_hook.list);

	/* 只读遍历找尾节点（读只读内存无需别名） */
	for (n = head->first; n; n = n->next)
		last = n;

	if (last) {
		/* 尾节点可能在 rodata：经别名写 last->next */
		prop_lsm_hook.list.pprev = &last->next;
		if (write_u64_via_alias((unsigned long)&last->next,
					(unsigned long)&prop_lsm_hook.list)) {
			pr_err("prop_spoof: 别名写入失败（挂载）\n");
			return -ENOMEM;
		}
	} else {
		/* 空链表：写 head->first */
		prop_lsm_hook.list.pprev = (struct hlist_node **)&head->first;
		if (write_u64_via_alias((unsigned long)&head->first,
					(unsigned long)&prop_lsm_hook.list)) {
			pr_err("prop_spoof: 别名写入失败（挂载空表）\n");
			return -ENOMEM;
		}
	}
	lsm_hook_linked = &prop_lsm_hook.list;
	pr_info("prop_spoof: LSM task_fix_setuid hook 已挂载\n");

	/* ---- file_open 钩子 ---- */
	{
		struct hlist_head *ohead = &shh->file_open;
		struct hlist_node *on = NULL, *on2;

		prop_lsm_hook_open.head = ohead;
		prop_lsm_hook_open.hook.file_open = lsm_file_open;
		prop_lsm_hook_open.lsm = "prop_spoof";
		prop_lsm_hook_open.list.next = NULL;
		INIT_HLIST_NODE(&prop_lsm_hook_open.list);
		for (on2 = ohead->first; on2; on2 = on2->next)
			on = on2;
		if (on) {
			prop_lsm_hook_open.list.pprev = &on->next;
			if (write_u64_via_alias((unsigned long)&on->next,
					(unsigned long)&prop_lsm_hook_open.list)) {
				pr_err("prop_spoof: file_open 钩子挂载失败\n");
				return -ENOMEM;
			}
		} else {
			prop_lsm_hook_open.list.pprev =
				(struct hlist_node **)&ohead->first;
			if (write_u64_via_alias((unsigned long)&ohead->first,
					(unsigned long)&prop_lsm_hook_open.list)) {
				pr_err("prop_spoof: file_open 钩子挂载失败(空表)\n");
				return -ENOMEM;
			}
		}
		pr_info("prop_spoof: LSM file_open hook 已挂载\n");
	}
	return 0;
}

static void lsm_remove(void)
{
	struct security_hook_heads *shh = (struct security_hook_heads *)shh_addr;
	struct hlist_head *head;
	struct hlist_node *prev = NULL, *n;

#ifdef PROP_SPOOF_BUILTIN
	if (!lsm_hook_linked)
#else
	if (!lsm_hook_linked || !shh_addr)
#endif
		return;
	head = &shh->task_fix_setuid;

	for (n = head->first; n; n = n->next) {
		if (n == &prop_lsm_hook.list)
			break;
		prev = n;
	}
	if (n != &prop_lsm_hook.list)
		return;

	if (prev)
		write_u64_via_alias((unsigned long)&prev->next,
				    (unsigned long)prop_lsm_hook.list.next);
	else
		write_u64_via_alias((unsigned long)&head->first,
				    (unsigned long)prop_lsm_hook.list.next);
	if (prop_lsm_hook.list.next)
		write_u64_via_alias((unsigned long)&prop_lsm_hook.list.next->pprev,
				    (unsigned long)(prev ?
					&prev->next :
					(struct hlist_node **)&head->first));

	/* 摘除 file_open 钩子 */
	{
		struct hlist_head *ohead = &shh->file_open;
		struct hlist_node *op = NULL, *on;

		for (on = ohead->first; on; on = on->next) {
			if (on == &prop_lsm_hook_open.list)
				break;
			op = on;
		}
		if (on == &prop_lsm_hook_open.list) {
			if (op)
				write_u64_via_alias((unsigned long)&op->next,
					(unsigned long)prop_lsm_hook_open.list.next);
			else
				write_u64_via_alias((unsigned long)&ohead->first,
					(unsigned long)prop_lsm_hook_open.list.next);
			if (prop_lsm_hook_open.list.next)
				write_u64_via_alias(
					(unsigned long)&prop_lsm_hook_open.list.next->pprev,
					(unsigned long)(op ? &op->next :
						(struct hlist_node **)&ohead->first));
		}
	}
	synchronize_rcu();
	lsm_hook_linked = NULL;
	pr_info("prop_spoof: LSM hook 已摘除\n");
}

static int __init prop_spoof_init(void)
{
#ifndef PROP_SPOOF_BUILTIN
	int ret;
#endif

#ifdef PROP_SPOOF_BUILTIN
	/* 内建：initcall 早于用户态，假属性区还没生成。
	 * 这里只建控制节点，等脚本准备好假文件后写 "start" 触发 */
	if (!proc_create("prop_spoof", 0600, NULL, &ctrl_ops))
		return -ENOMEM;
	if (!proc_create("prop_spoof_cfg", 0600, NULL, &cfg_ops)) {
		remove_proc_entry("prop_spoof", NULL);
		return -ENOMEM;
	}
	pr_info("prop_spoof: builtin 已注册，等待 cfg start\n");
	return 0;
#else
	parse_target_uids();
	ret = build_pat_parse();
	if (ret)
		return ret;
	if (!proc_create("prop_spoof", 0600, NULL, &ctrl_ops)) {
		build_pat_free();
		return -ENOMEM;
	}

	ret = hook_install();
	if (ret)
		goto err;
	ret = prop_hooks_install();
	if (ret)
		goto err2;
	ret = lsm_install();
	if (ret)
		goto err3;
	return 0;
err3:
	prop_hooks_remove();
err2:
	hook_remove();
err:
	remove_proc_entry("prop_spoof", NULL);
	build_pat_free();
	return ret;
#endif
}

static void __exit prop_spoof_exit(void)
{
#ifdef PROP_SPOOF_BUILTIN
	cancel_delayed_work_sync(&prop_hide_work);
#endif
	lsm_remove();
	prop_hooks_remove();
	hook_remove();
#ifdef PROP_SPOOF_BUILTIN
	if (!nodes_hidden) {
		remove_proc_entry("prop_spoof", NULL);
		remove_proc_entry("prop_spoof_cfg", NULL);
	}
#else
	remove_proc_entry("prop_spoof", NULL);
#endif
	mutex_lock(&fake_lock);
	vfree(fake_buf);
	fake_buf = NULL;
	mutex_unlock(&fake_lock);
	build_pat_free();
}

module_init(prop_spoof_init);
module_exit(prop_spoof_exit);

#ifndef PROP_SPOOF_BUILTIN
/* clean.ko 本地编译：手工提供 this_module 节（内建时由内核自身提供） */
struct module __this_module
	__attribute__((section(".gnu.linkonce.this_module"), aligned(64))) = {
	.name = "prop_spoof",
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
};
#endif
