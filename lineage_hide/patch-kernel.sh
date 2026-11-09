#!/usr/bin/env bash
# patch-kernel.sh —— procfs 路径显示清洗（自建版，替代上游已删除的同名脚本）
#
# 把 /proc/<pid>/{fd,map_files,maps,smaps,numa_maps} 里路径中的 ROM 标识
# （lineage/crdroid/aospa/...）等长改写为 xx…x，只对 uid>=10000 的应用生效。
# 只改「显示字符串」，不影响文件访问。
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

open(hdr_path, 'w').write(HEADER)
print('写入', hdr_path)

def patch(path, includes=None, inserts=None):
    src = open(path, encoding='utf-8', errors='surrogateescape').read()
    if 'lineage_hide.h' in src:
        print('已打过补丁:', path)
        return True
    if includes:
        anchor, line = includes
        if anchor not in src:
            print('error: 找不到 include 锚点:', path, file=sys.stderr)
            return False
        src = src.replace(anchor, line + '\n' + anchor, 1)
    for anchor, snippet, where in inserts:
        if anchor not in src:
            print('error: 找不到锚点 (%s): %s' % (anchor, path), file=sys.stderr)
            return False
        if where == 'after':
            src = src.replace(anchor, anchor + snippet, 1)
        else:
            src = src.replace(anchor, snippet + anchor, 1)
    open(path, 'w', encoding='utf-8', errors='surrogateescape').write(src)
    print('已打补丁:', path)
    return True

ok = True

# ---- 1) fs/seq_file.c：seq_path() 里 d_path 之后清洗（覆盖 maps/smaps/numa_maps）----
seq = os.path.join(kdir, 'fs/seq_file.c')
s = open(seq, encoding='utf-8', errors='surrogateescape').read()
if 'lineage_hide.h' in s:
    print('已打过补丁:', seq)
else:
    inc_anchor = '#include <linux/seq_file.h>'
    if inc_anchor not in s:
        inc_anchor = '#include <linux/uaccess.h>'
    if inc_anchor not in s:
        print('error: seq_file.c 找不到 include 锚点', file=sys.stderr)
        ok = False
    else:
        s = s.replace(inc_anchor, inc_anchor + '\n#include <linux/lineage_hide.h>', 1)
        # seq_path() 中的 d_path 调用后清洗
        dpath = 'char *p = d_path(path, buf, size);'
        if dpath not in s:
            print('error: seq_file.c 找不到 d_path 锚点', file=sys.stderr)
            ok = False
        else:
            s = s.replace(
                dpath,
                dpath + '\n\t\tif (!IS_ERR(p))\n\t\t\tlineage_hide_scrub_rom_names(p);',
                1)
            open(seq, 'w', encoding='utf-8', errors='surrogateescape').write(s)
            print('已打补丁:', seq)

# ---- 2) fs/proc/base.c：do_proc_readlink() 里 d_path 结果清洗（覆盖 fd / map_files）----
base = os.path.join(kdir, 'fs/proc/base.c')
b = open(base, encoding='utf-8', errors='surrogateescape').read()
if 'lineage_hide.h' in b:
    print('已打过补丁:', base)
else:
    inc_anchor = '#include <linux/capability.h>'
    if inc_anchor not in b:
        print('error: base.c 找不到 include 锚点', file=sys.stderr)
        ok = False
    else:
        b = b.replace(inc_anchor, inc_anchor + '\n#include <linux/lineage_hide.h>', 1)
        # do_proc_readlink 里 pathname = d_path(...) 之后、IS_ERR 检查之后插入
        marker = 'pathname = d_path(path, tmp,'
        idx = b.find(marker)
        if idx < 0:
            print('error: base.c 找不到 do_proc_readlink 的 d_path', file=sys.stderr)
            ok = False
        else:
            err_block = b.find('IS_ERR(pathname)', idx)
            brace = b.find('}', b.find('goto out;', err_block)) if err_block > 0 else -1
            if err_block < 0 or brace < 0:
                print('error: base.c 找不到 IS_ERR 处理块', file=sys.stderr)
                ok = False
            else:
                ins = brace + 1
                b = b[:ins] + '\n\tlineage_hide_scrub_rom_names(pathname);' + b[ins:]
                open(base, 'w', encoding='utf-8', errors='surrogateescape').write(b)
                print('已打补丁:', base)

sys.exit(0 if ok else 2)
PY

echo "[OK] procfs 路径清洗补丁完成"
