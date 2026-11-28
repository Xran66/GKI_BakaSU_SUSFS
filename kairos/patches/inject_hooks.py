#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
inject_hooks.py — 把 MEMX 的调用点注入内核源码（锚点方式，不依赖行号）

用法: python3 inject_hooks.py <KERNEL_DIR>

为什么用锚点而不是 .patch：
  rebase 到不同 6.6.x 小版本时上下文行号会漂，.patch 必然 fuzz 或失败；
  锚点只匹配"这一行代码本身"，6.6 全系都稳定。

两个注入点（对应原版的两次 register_kprobe）：
  1) net/socket.c    : __sys_sendto()             —— 陀螺仪改写
  2) kernel/reboot.c : SYSCALL_DEFINE4(reboot...) —— 隐蔽握手 + 关停清理
"""
import os
import re
import sys

# ---------------------------------------------------------------- socket.c

SOCKET_DECL = """/*
 * MEMX: 陀螺仪注入入口。
 * 原版是 register_kprobe("__arm64_sys_sendto")，改成源码级调用后
 * /sys/kernel/debug/kprobes/list 里不会出现任何 kprobe 条目。
 */
#ifdef CONFIG_MEMX_GYRO_HOOK
extern bool memx_active(void);
extern void memx_sendto_probe(void __user *buf, size_t len);
#endif

"""

SOCKET_CALL = """#ifdef CONFIG_MEMX_GYRO_HOOK
	/* 必须在 import_single_range() 之前：hook 改的是用户缓冲本身；
	 * import 之后改的只是本地 iov_iter 的副本，发出去的还是原数据。 */
	if (memx_active())
		memx_sendto_probe(buff, len);
#endif
"""

SOCKET_FUNC = "int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,"
SOCKET_ANCHOR = "\terr = import_single_range(ITER_SOURCE, buff, len, &iov, &msg.msg_iter);"

# ---------------------------------------------------------------- reboot.c

REBOOT_DECL = """/*
 * MEMX: reboot() 隐蔽信令通道 + 关机前清理。
 * 原版是 register_kprobe("__arm64_sys_reboot") 的 pre_handler。
 */
#ifdef CONFIG_MEMX
extern bool memx_active(void);
extern bool memx_reboot_filter(int magic1, int magic2, unsigned int cmd,
			       void __user *arg);
#endif

"""

REBOOT_CALL = """#ifdef CONFIG_MEMX
	/* 客户端用 reboot(0x48931414, x, 0x51239123, &out) 取 ghost fd。
	 * 与 .ko 版行为对齐：原版 kprobe 只做 task_work_add 就放行，
	 * 非 root 客户端随后在 CAP_SYS_BOOT 检查处拿到 -EPERM。
	 * 这里显式返回 -EPERM —— 既保持客户端看到的 errno 一致，
	 * 又避免 root 客户端真的把机器重启掉（原版这个洞是真实存在的）。 */
	if (memx_active() && memx_reboot_filter(magic1, magic2, cmd, arg))
		return -EPERM;
#endif
"""

REBOOT_ANCHOR = re.compile(
    r"(SYSCALL_DEFINE4\(reboot, int, magic1, int, magic2, unsigned int, cmd,\s*\n"
    r"\t\tvoid __user \*, arg\)\s*\n\{\s*\n"
    r"\tstruct pid_namespace \*pid_ns = task_active_pid_ns\(current\);\s*\n"
    r"\tchar buffer\[256\];\s*\n"
    r"\tint ret = 0;\s*\n)"
)


def read(path):
    with open(path, "r", encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", errors="surrogateescape") as f:
        f.write(text)


def patch_socket(kdir):
    path = os.path.join(kdir, "net", "socket.c")
    s = read(path)
    if "memx_sendto_probe" in s:
        print("  net/socket.c: 已注入，跳过")
        return True

    n = s.count(SOCKET_ANCHOR)
    if n != 1:
        print("  net/socket.c: !! 锚点出现 %d 次（应为 1），拒绝注入" % n)
        return False

    s = s.replace(SOCKET_ANCHOR, SOCKET_CALL + SOCKET_ANCHOR, 1)

    if SOCKET_FUNC in s:
        s = s.replace(SOCKET_FUNC, SOCKET_DECL + SOCKET_FUNC, 1)
    else:
        print("  net/socket.c: !! 找不到 __sys_sendto 定义，声明改插文件头")
        s = SOCKET_DECL + s

    write(path, s)
    print("  net/socket.c: 注入成功（__sys_sendto 入口）")
    return True


def patch_reboot(kdir):
    path = os.path.join(kdir, "kernel", "reboot.c")
    s = read(path)
    if "memx_reboot_filter" in s:
        print("  kernel/reboot.c: 已注入，跳过")
        return True

    m = REBOOT_ANCHOR.search(s)
    if not m:
        print("  kernel/reboot.c: !! 找不到 SYSCALL_DEFINE4(reboot ...) 函数头")
        return False

    s = s[:m.end()] + "\n" + REBOOT_CALL + s[m.end():]

    idx = s.find("SYSCALL_DEFINE4(reboot")
    s = s[:idx] + REBOOT_DECL + s[idx:]

    write(path, s)
    print("  kernel/reboot.c: 注入成功（SYSCALL_DEFINE4(reboot) 入口）")
    return True


def main():
    if len(sys.argv) < 2:
        print("用法: inject_hooks.py <KERNEL_DIR>")
        return 2
    kdir = sys.argv[1]
    print("[memx] 注入调用点: %s" % kdir)

    ok = True
    ok &= patch_socket(kdir)
    ok &= patch_reboot(kdir)

    sc = read(os.path.join(kdir, "net", "socket.c"))
    rc = read(os.path.join(kdir, "kernel", "reboot.c"))
    print("[memx] 校验: socket.c -> %s, reboot.c -> %s"
          % ("OK" if "memx_sendto_probe(buff, len)" in sc else "MISSING",
             "OK" if "memx_reboot_filter(magic1, magic2, cmd, arg)" in rc else "MISSING"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
