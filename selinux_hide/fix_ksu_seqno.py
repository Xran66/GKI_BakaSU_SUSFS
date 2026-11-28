#!/usr/bin/env python3
"""Make /sys/fs/selinux/status and /sys/fs/selinux/access agree on seqno.

BakaSU's selinux_hide serves a static fake status page (sequence=0,
policyload=0 on <6.10) while my_write_access() hard-codes avd.seqno=1.
AppZygote-based detectors (DirtySepolicy / Duck-Detector family) cross-check
the two and flag "status.sequence/policyload unexpected".

This rewrites both sides to use one shared variable derived from the clean
policy's single load: policyload=1, sequence=2, avd.seqno=1. It is idempotent
and refuses to guess when upstream text changes.
"""
import pathlib
import sys

ANCHOR_VAR = "__maybe_static struct page *fake_status = NULL;"
ANCHOR_SEQ = "    avd.seqno = 1;"
ANCHOR_BLOCK = """    if (ksu_late_loaded) {
        // In late_load mode the loader may have reloaded sepolicy before us,
        // so the captured page is not stock. Serve what a stock boot ends
        // with instead: creation sentinel below 6.10, one load plus one
        // setenforce above.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
        new_status->sequence = 4;
        new_status->policyload = 1;
#else
        new_status->sequence = 0;
        new_status->policyload = 0;
#endif
        if (!new_status->enforcing) {
            new_status->enforcing = 1;
        }
    }
"""

NEW_BLOCK = """    /* status.sequence / status.policyload and the avd.seqno returned by
     * /sys/fs/selinux/access must come from the same source. The stock
     * 0/0 page paired with a hard-coded seqno=1 is the exact fingerprint
     * flagged as "sequence/policyload unexpected" by AppZygote probes.
     * One policy load -> policyload=1, sequence=2 (two seqlock steps). */
    ksu_hidden_policy_seqno = 1;
    new_status->policyload = ksu_hidden_policy_seqno;
    new_status->sequence = 2 * ksu_hidden_policy_seqno;
    if (!new_status->enforcing) {
        new_status->enforcing = 1;
    }
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: fix_ksu_seqno.py <path-to-selinux_hide.c>", file=sys.stderr)
        return 2
    p = pathlib.Path(sys.argv[1])
    if not p.is_file():
        print(f"::warning::{p} not found, skip seqno fix")
        return 0

    s = p.read_text(encoding="utf-8")
    if "ksu_hidden_policy_seqno" in s:
        print("seqno fix already applied, skip")
        return 0

    for name, needle in (("fake_status declaration", ANCHOR_VAR),
                         ("avd.seqno assignment", ANCHOR_SEQ),
                         ("fake_status init block", ANCHOR_BLOCK)):
        if s.count(needle) != 1:
            print(f"::warning::{name} not uniquely matched "
                  f"(count={s.count(needle)}), skip seqno fix")
            return 0

    s = s.replace(
        ANCHOR_VAR,
        ANCHOR_VAR + "\n"
        "/* single source of truth for /sys/fs/selinux/status and access seqno */\n"
        "static u32 ksu_hidden_policy_seqno __read_mostly = 1;",
    )
    s = s.replace(ANCHOR_SEQ, "    avd.seqno = ksu_hidden_policy_seqno;")
    s = s.replace(ANCHOR_BLOCK, NEW_BLOCK)
    p.write_text(s, encoding="utf-8")
    print("BakaSU selinux_hide.c: status/access seqno unified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
