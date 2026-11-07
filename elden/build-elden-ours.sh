#!/usr/bin/env bash
set -euo pipefail
BUILD_NUMBER=$(/usr/bin/shuf -i 10000000-99999999 -n 1)
export BUILD_NUMBER

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$ROOT/boot.conf"
WORK=$ROOT/.work
KERNEL=$WORK/kernel
DIST=$WORK/dist
JOBS=${JOBS:-8}

# --- Xran66 扩展开关 ---
# ADD_PROPSPOOF=1    : 内建 prop_spoof（编译期惰性，cfg start 前不生效）
# ADD_LINEAGEHIDE=1  : 应用 Lineage_Hide procfs 清洗补丁（bootloop 嫌疑，默认关）
ADD_PROPSPOOF=${ADD_PROPSPOOF:-1}
ADD_LINEAGEHIDE=${ADD_LINEAGEHIDE:-0}
PROP_SPOOF_SRC=${PROP_SPOOF_SRC:-$ROOT/prop_spoof.c}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

init_workspace() {
    [[ $WORK == "$ROOT/.work" && ! -L $WORK ]] || fail "invalid workspace"
    mkdir -p "$WORK"
    if [[ ! -f $WORK/.elden-kernel-workspace ]]; then
        [[ -z $(find "$WORK" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
            fail "refusing an existing, unowned workspace: $WORK"
        printf 'Generated Elden kernel workspace.\n' > "$WORK/.elden-kernel-workspace"
    fi
}

sync_git() {
    local path=$1 url=$2 branch=$3 full=${4:-false}
    [[ $path == "$WORK/"* && ! -L $path ]] || fail "invalid checkout: $path"
    if [[ ! -e $path ]]; then
        local depth=()
        [[ $full == true ]] || depth=(--depth=1)
        git clone --single-branch --branch "$branch" "${depth[@]}" "$url" "$path"
    else
        [[ $(git -C "$path" remote get-url origin) == "$url" ]] || fail "wrong origin: $path"
    fi
    if [[ $full == true ]]; then
        local shallow=()
        [[ $(git -C "$path" rev-parse --is-shallow-repository) == false ]] || shallow=(--unshallow)
        git -C "$path" fetch "${shallow[@]}" --tags origin "$branch"
    else
        git -C "$path" fetch --depth=1 origin "$branch"
    fi
    git -C "$path" checkout --force -B "$branch" FETCH_HEAD
    git -C "$path" clean -fd
}

sync_sources() {
    [[ $KERNEL == "$WORK/kernel" && ! -L $KERNEL && ! -L $KERNEL/common ]] || fail "invalid kernel workspace"
    mkdir -p "$KERNEL"
    if [[ -e $KERNEL/common/.git ]]; then
        git -C "$KERNEL/common" reset --hard HEAD
        git -C "$KERNEL/common" clean -fd
    fi
    (
        cd "$KERNEL"
        repo init -q -u https://android.googlesource.com/kernel/manifest \
            -b common-android16-6.12 --depth=1
        repo sync -c -d -j"$JOBS" --no-tags --no-clone-bundle --no-verify --no-auto-gc
    )
    sync_git "$WORK/BakaSU" https://github.com/Baka-SU/BakaSU.git main true
    sync_git "$WORK/susfs" https://gitlab.com/simonpunk/susfs4ksu.git gki-android16-6.12
    sync_git "$WORK/AnyKernel3" https://github.com/osm0sis/AnyKernel3.git master
    git -C "$WORK/AnyKernel3" fetch --depth=1 origin \
        +refs/heads/arm64-tools:refs/remotes/origin/arm64-tools
    if [[ $ADD_LINEAGEHIDE == 1 ]]; then
        sync_git "$WORK/lineage_hide" https://github.com/null07089/Lineage_Hide.git main
    fi
}

apply_patch() {
    local tree=$1 patch=$2
    git -C "$tree" apply --check "$patch"
    git -C "$tree" apply "$patch"
}

write_version() {
    local source=$1 output=$2
    python3 -I - "$source" "$output" <<'PY'
from pathlib import Path
import re
import subprocess
import sys
source, output = map(Path, sys.argv[1:])
def git(*args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
assert git('rev-parse', '--is-shallow-repository') == 'false', 'BakaSU needs full history'
tag = subprocess.run(['git', '-C', str(source), 'describe', '--abbrev=0', '--tags'],
                     text=True, capture_output=True)
values = {
    'KSU_LOCAL_VERSION': git('rev-list', '--count', 'HEAD'),
    'KSU_TAG_NAME': tag.stdout.strip() if tag.returncode == 0 else 'untagged',
    'KSU_COMMIT_SHA': git('rev-parse', '--short=8', 'HEAD') + '-dirty',
    'KSU_BRANCH_NAME': git('branch', '--show-current') or 'detached',
}
# The generated payload includes our Kleaf adapter, so do not claim a pristine upstream build.
assert all(re.fullmatch(r'[A-Za-z0-9._/+~-]+', value) for value in values.values())
output.write_text(''.join(f'{key} := {value}\n' for key, value in values.items()))
PY
}

integrate() {
    local common=$KERNEL/common
    apply_patch "$common" "$WORK/susfs/kernel_patches/50_add_susfs_in_gki-android16-6.12.patch"
    cp "$WORK/susfs/kernel_patches/fs/susfs.c" "$common/fs/susfs.c"
    cp "$WORK/susfs/kernel_patches/include/linux/"susfs*.h "$common/include/linux/"
    mkdir -p "$common/drivers/bakasu"
    git -C "$WORK/BakaSU" archive HEAD kernel uapi LICENSE |
        tar -x -C "$common/drivers/bakasu"
    printf '\nsource "drivers/bakasu/kernel/Kconfig"\n' >> "$common/drivers/Kconfig"
    printf '\nobj-$(CONFIG_KSU) += bakasu/kernel/\n' >> "$common/drivers/Makefile"
    cp "$ROOT/kernel.fragment" "$common/arch/arm64/configs/elden.fragment"
    printf '\nexports_files(["arch/arm64/configs/elden.fragment"])\n' >> "$common/BUILD.bazel"
    local patch
    for patch in "$ROOT"/patches/*.patch; do
        apply_patch "$common" "$patch"
    done
    write_version "$WORK/BakaSU" "$common/drivers/bakasu/kernel/elden-version.mk"
    if [[ $ADD_PROPSPOOF == 1 ]]; then
        mkdir -p "$common/drivers/prop_spoof"
        cp "$PROP_SPOOF_SRC" "$common/drivers/prop_spoof/prop_spoof.c"
        printf 'ccflags-y += -DPROP_SPOOF_BUILTIN\nobj-y += prop_spoof.o\n' \
            > "$common/drivers/prop_spoof/Makefile"
        printf '\nobj-y += prop_spoof/\n' >> "$common/drivers/Makefile"
        echo "prop_spoof: integrated (builtin, inert until cfg start)"
    fi
    if [[ $ADD_LINEAGEHIDE == 1 ]]; then
        bash "$ROOT/lineage_hide/patch-kernel.sh" "$common"
        echo "Lineage_Hide: procfs scrub patches applied"
    fi
}

check_config() {
    local config=$1
    grep -qx 'CONFIG_KSU=y' "$config" || fail "BakaSU is not built in"
    grep -qx 'CONFIG_KSU_SUSFS=y' "$config" || fail "SUSFS is not enabled"
    grep -qx 'CONFIG_MQ_IOSCHED_ADIOS=y' "$config" || fail "ADIOS is not built in"
    grep -qx 'CONFIG_MQ_IOSCHED_DEFAULT_ADIOS=y' "$config" || fail "ADIOS is not the default I/O scheduler"
    grep -qx 'CONFIG_TCP_CONG_BBR3=y' "$config" || fail "BBRv3 is not built in"
    grep -qx 'CONFIG_DEFAULT_TCP_CONG="bbr3"' "$config" || fail "BBRv3 is not the default TCP congestion control"
    grep -qx 'CONFIG_NET_SCH_FQ=y' "$config" || fail "FQ is not built in"
    grep -qx 'CONFIG_DEFAULT_NET_SCH="fq"' "$config" || fail "FQ is not the default qdisc"
    if grep -qx 'CONFIG_MODULE_SIG_PROTECT=y' "$config"; then
        fail "MODULE_SIG_PROTECT is still enabled"
    fi
}

build_image() {
    rm -rf -- "$DIST"
    mkdir "$DIST"
    (
        cd "$KERNEL"
        ./tools/bazel --local_startup_timeout_secs=600 run --config=stamp --jobs="$JOBS" --make_jobs="$JOBS" \
            --defconfig_fragment=//common:arch/arm64/configs/elden.fragment \
            //common:kernel_aarch64_dist -- --destdir="$DIST"
    )
    [[ -s $DIST/Image ]] || fail "build produced no Image"
    check_config "$DIST/kernel_aarch64_dot_config"
}

sign_boot() {
    local input=$1 output=$2
    local avbtool=$KERNEL/prebuilts/kernel-build-tools/linux-x86/bin/avbtool
    local key=$KERNEL/$AVB_KEY_PATH
    [[ -s $input ]] || fail "build produced no boot image"
    cp "$input" "$output"
    "$avbtool" erase_footer --image "$output"
    "$avbtool" add_hash_footer --image "$output" \
        --partition_name boot --partition_size "$BOOT_PARTITION_SIZE" \
        --algorithm "$AVB_ALGORITHM" --key "$key" \
        --rollback_index "$AVB_ROLLBACK_INDEX" \
        --prop "com.android.build.boot.os_version:$AVB_OS_VERSION" \
        --prop "com.android.build.boot.security_patch:$AVB_SECURITY_PATCH"
    "$avbtool" verify_image --image "$output" --key "$key"
}

package_boot() {
    local boot=$1 upstream=$2 destination=$3
    [[ -s $boot ]] || fail "cannot package a missing or empty boot image"
    [[ ! -e $destination && ! -L $destination ]] || fail "refusing to overwrite $destination"
    local staging=$WORK/package
    rm -rf -- "$staging"
    mkdir "$staging"
    git -C "$upstream" archive HEAD | tar -x -C "$staging"
    git -C "$upstream" archive refs/remotes/origin/arm64-tools | tar -x -C "$staging/tools"
    local updater=$staging/META-INF/com/google/android/update-binary
    [[ $(grep -Fxc '  $bb --install -s bin;' "$updater") == 1 ]] || fail "AnyKernel3 BusyBox setup changed"
    sed -i 's/^  \$bb --install -s bin;$/  $bb --install bin;/' "$updater"
    rm -f -- "$staging/anykernel.sh" "$staging/Image" "$staging/boot.img"
    cp "$ROOT/anykernel.sh" "$staging/anykernel.sh"
    chmod 755 "$staging/anykernel.sh"
    cp "$boot" "$staging/boot.img"
    (cd "$staging" && zip -qr9 "$destination" .)
    python3 -I - "$destination" "$boot" <<'PY'
import hashlib
from pathlib import Path
import sys
import zipfile
archive, boot = sys.argv[1:]
with zipfile.ZipFile(archive) as package:
    assert package.namelist().count('boot.img') == 1
    assert 'Image' not in package.namelist()
    assert not any(name.startswith('.git/') for name in package.namelist())
    assert package.testzip() is None, 'corrupt ZIP'
    with package.open('boot.img') as stream, Path(boot).open('rb') as expected:
        assert hashlib.file_digest(stream, 'sha256').digest() == hashlib.file_digest(expected, 'sha256').digest()
PY
}

main() {
    [[ $# == 0 ]] || fail "Usage: $0 (optional environment: JOBS)"
    [[ $JOBS =~ ^[1-9][0-9]*$ ]] || fail "JOBS must be a positive integer"
    local tool
    for tool in repo git python3 zip tar sha256sum openssl; do
        command -v "$tool" >/dev/null || fail "missing tool: $tool"
    done
    init_workspace
    sync_sources
    integrate
    build_image
    sign_boot "$DIST/boot.img" "$WORK/boot.img"
    local release=$WORK/release
    local destination=$ROOT/out/$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$WORK/BakaSU" rev-parse --short=8 HEAD)
    [[ ! -e $destination && ! -L $destination ]] || fail "refusing to overwrite $destination"
    rm -rf -- "$release"
    mkdir "$release"
    package_boot "$WORK/boot.img" "$WORK/AnyKernel3" "$release/elden-kernel.zip"
    cp "$DIST/Image" "$release/Image"
    cp "$WORK/boot.img" "$release/boot.img"
    cp "$DIST/kernel_aarch64_dot_config" "$release/kernel.config"
    "$KERNEL/prebuilts/kernel-build-tools/linux-x86/bin/avbtool" info_image \
        --image "$release/boot.img" > "$release/avb-info.txt"
    (
        for tool in kernel/common BakaSU susfs AnyKernel3; do
            printf '%s %s\n' "$tool" "$(git -C "$WORK/$tool" rev-parse HEAD)"
        done
        printf 'AnyKernel3-tools %s\n' "$(git -C "$WORK/AnyKernel3" rev-parse refs/remotes/origin/arm64-tools)"
        printf 'BUILD_NUMBER %s\n' "$BUILD_NUMBER"
        cat "$KERNEL/common/drivers/bakasu/kernel/elden-version.mk"
        cd "$ROOT"
        sha256sum patches/*.patch kernel.fragment boot.conf anykernel.sh build-bakasu-elden.sh
    ) > "$release/sources.txt"
    (cd "$KERNEL" && repo manifest -r -o "$release/manifest.xml")
    (
        cd "$release"
        sha256sum Image boot.img elden-kernel.zip kernel.config sources.txt manifest.xml avb-info.txt > SHA256SUMS
    )
    mkdir -p "$ROOT/out"
    mv -T -- "$release" "$destination"
    printf '\nBuilt: %s\n' "$destination"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
