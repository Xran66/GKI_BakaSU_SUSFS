#!/usr/bin/env bash
# patch-kernel.sh —— procfs 路径显示清洗（自建版，替代上游已删除的同名脚本）
#
# 把 /proc/<pid>/{fd,map_files,maps,smaps,numa_maps} 里路径中的 ROM 标识
# （lineage/crdroid/aospa/...）等长改写，仅对 uid>=10000 的应用生效。
# 只改「显示字符串」，不影响文件访问。锚点缺失时只警告、不破坏源码。
#
# 用法：patch-kernel.sh <kernel/common 目录>
set -euo pipefail

KDIR=${1:?用法: patch-kernel.sh <kernel/common 目录>}
[ -f "$KDIR/fs/seq_file.c" ] || { echo "error: 不是内核源码目录: $KDIR" >&2; exit 1; }

python3 - "$KDIR" <<'PY'
import os
import sys

kdir = sys.argv[1]
hdr_path = os.path.join(kdir, 'include/linux/lineage_hide.h')

HEADER = '''/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LINEAGE_HIDE_H
#define _LINUX_LINEAGE_HIDE_H

#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#define LINEAGE_HIDE_APP_UID_MIN 10000

static inline bool lineage_hide_active(void)
{
	return current_uid().val >= LINEAGE_HIDE_APP_UID_MIN;
}

/* 命中 ROM 标识时把最后一个字符改成 'x'：等长改写，不改路径语义 */
static inline void lineage_hide_scrub_rom_names(char *path)
{
	static const char *const rom_names[] = {
		"lineage", "crdroid", "aospa", "pixelexperience",
		"omnirom", "protonaosp",
	};
	size_t i, len;
	char *p;

	if (!path || !lineage_hide_active())
		return;

	for (i = 0; i < ARRAY_SIZE(rom_names); i++) {
		len = strlen(rom_names[i]);
		for (p = path; *p; p++)
			if (!strncasecmp(p, rom_names[i], len))
				p[len - 1] = 'x';
	}
}

#endif /* _LINUX_LINEAGE_HIDE_H */
'''

with open(hdr_path, 'w') as f:
    f.write(HEADER)
print('写入', hdr_path)

ok = True

# ---- 1) fs/seq_file.c：seq_path() 的 d_path 之后清洗（覆盖 maps/smaps/numa_maps）----
seq = os.path.join(kdir, 'fs/seq_file.c')
s = open(seq, encoding='utf-8', errors='surrogateescape').read()
if 'lineage_hide.h' in s:
    print('已打过补丁:', seq)
else:
    inc = '#include <linux/seq_file.h>'
    if inc not in s:
        inc = '#include <linux/uaccess.h>'
    anchor = 'char *p = d_path(path, buf, size);'
    if inc not in s or anchor not in s:
        print('WARN: seq_file.c 锚点缺失，跳过', file=sys.stderr)
        ok = False
    else:
        s = s.replace(inc, inc + '\n#include <linux/lineage_hide.h>', 1)
        ins = anchor + '\n\t\tif (!IS_ERR(p))\n\t\t\tlineage_hide_scrub_rom_names(p);'
        s = s.replace(anchor, ins, 1)
        with open(seq, 'w', encoding='utf-8', errors='surrogateescape') as f:
            f.write(s)
        print('已打补丁:', seq)

# ---- 2) fs/proc/base.c：do_proc_readlink() 长度计算前清洗（覆盖 fd / map_files）----
base = os.path.join(kdir, 'fs/proc/base.c')
b = open(base, encoding='utf-8', errors='surrogateescape').read()
if 'lineage_hide.h' in b:
    print('已打过补丁:', base)
else:
    inc = '#include <linux/capability.h>'
    variants = [
        'len = tmp + PATH_MAX - 1 - pathname;',
        'len = tmp + PAGE_SIZE - 1 - pathname;',
    ]
    hit = next((v for v in variants if v in b), None)
    if inc not in b or hit is None:
        print('WARN: base.c 锚点缺失，跳过', file=sys.stderr)
        ok = False
    else:
        b = b.replace(inc, inc + '\n#include <linux/lineage_hide.h>', 1)
        b = b.replace(hit, '\tlineage_hide_scrub_rom_names(pathname);\n\t' + hit, 1)
        with open(base, 'w', encoding='utf-8', errors='surrogateescape') as f:
            f.write(b)
        print('已打补丁:', base)

sys.exit(0 if ok else 2)
PY

echo "[OK] procfs 路径清洗补丁完成"
