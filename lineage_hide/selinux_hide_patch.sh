#!/usr/bin/env bash
# selinux_hide_patch.sh —— 加固 BakaSU 的 selinux_hide 特性（自建版，替代上游已删除的同名脚本）
#
# 背景：BakaSU 的 selinux_hide 用「开机留存的策略副本(backup_sepolicy)」回答应用的
#       selinuxfs 查询。类原生 GSI 是 userdebug 构建，策略里带 adbroot/su 等特权域，
#       检测器通过 /sys/fs/selinux/{context,access} 与 setprocattr 探测这些域即可判定
#       「策略被篡改」。
# 本补丁：对 uid >= 10000 的应用进程，在三条探针入口直接返回 -EINVAL，
#       使探测无论 policy 内容如何都拿不到肯定答案；root/shell(uid<10000) 不受影响。
#
# 用法：selinux_hide_patch.sh <BakaSU 源码根目录>   （其中含 kernel/feature/selinux_hide.c）
set -euo pipefail

ROOT=${1:?用法: selinux_hide_patch.sh <BakaSU 根目录>}
F="$ROOT/kernel/feature/selinux_hide.c"
[ -f "$F" ] || { echo "error: 找不到 $F" >&2; exit 1; }

python3 - "$F" <<'PY'
import re
import sys

path = sys.argv[1]
src = open(path, encoding='utf-8', errors='surrogateescape').read()

MARK = "/* lineage_hide_guard: 应用探测特权域一律拒绝 */"

if MARK in src:
    print("selinux_hide: 已打过补丁，跳过")
    sys.exit(0)

HELPER = r'''
/* lineage_hide_guard: 应用探测特权域一律拒绝 */
static inline bool lineage_hide_deny_probe(const char *buf, size_t size)
{
	static const char *const deny[] = {
		":adbroot:", ":su:", ":fsck_untrusted:", ":magisk:", ":ksu:",
	};
	size_t i, j, dl;

	if (!buf || !size)
		return false;
	if (ksu_get_uid_t(current_uid()) < 10000)
		return false;
	for (i = 0; i < ARRAY_SIZE(deny); i++) {
		dl = strlen(deny[i]);
		if (!dl || dl > size)
			continue;
		for (j = 0; j + dl <= size; j++)
			if (!memcmp(buf + j, deny[i], dl))
				return true;
	}
	return false;
}
'''

# ---- 1) 插入 helper（放在 my_write_context 定义之前）----
anchor = "static inline u32 current_sid(void)"
if anchor not in src:
    print("error: 找不到 current_sid 锚点", file=sys.stderr)
    sys.exit(1)
src = src.replace(anchor, HELPER + "\n" + anchor, 1)

# ---- 2) my_write_context / my_write_access：函数体开头加守卫 ----
def insert_guard(text, sig_regex, ret="-EINVAL"):
    m = re.search(sig_regex, text)
    if not m:
        return text, False
    brace = text.find("{", m.end() - 1)
    if brace < 0:
        return text, False
    guard = (
        "\n    if (lineage_hide_deny_probe(buf, size))\n"
        f"        return {ret};\n"
    )
    return text[:brace + 1] + guard + text[brace + 1:], True

src, ok1 = insert_guard(src, r"ssize_t\s+my_write_context\s*\([^)]*\)")
src, ok2 = insert_guard(src, r"ssize_t\s+my_write_access\s*\([^)]*\)")
if not (ok1 and ok2):
    print(f"error: my_write_context={ok1} my_write_access={ok2} 定位失败", file=sys.stderr)
    sys.exit(1)

# ---- 3) ksu_handle_selinux_setprocattr：value 是 char*，用 size 判定 ----
#    注意该函数有两种原型（#if/#else），锚定最后一个原型，再找其后的函数体 '{'
pos = src.rfind("int __nocfi ksu_handle_selinux_setprocattr")
if pos < 0:
    print("error: 找不到 ksu_handle_selinux_setprocattr", file=sys.stderr)
    sys.exit(1)
brace = src.find("\n{", pos)
if brace < 0:
    print("error: 找不到 setprocattr 函数体起点", file=sys.stderr)
    sys.exit(1)
brace += 1  # 指向 '{'
src = (src[:brace + 1] +
       "\n    if (lineage_hide_deny_probe((const char *)value, size))\n"
       "        return -EINVAL;\n" +
       src[brace + 1:])

open(path, 'w', encoding='utf-8', errors='surrogateescape').write(src)
print("selinux_hide: 三处探针守卫已插入")
PY

echo "[OK] selinux_hide 加固完成: $F"
