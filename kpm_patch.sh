#!/bin/bash
# =============================================================
# KPM 恢复补丁 - 在最新 ReSukiSU 上游代码上重新启用 KPM 支持
# 
# 背景: ReSukiSU 上游在 commit faac3098 (2026-06-06) 中移除了
#       KPM (KernelPatch Module) 支持。本脚本将 KPM 代码恢复
#       到最新上游版本中。
#
# 用法: bash kpm_patch.sh [KernelSU目录]
#       默认目录为 kernel_workspace/KernelSU
# =============================================================

set -e

KSU_DIR="${1:-kernel_workspace/KernelSU}"

log_info()  { echo "[KPM-PATCH] $1"; }
log_warn()  { echo "[KPM-PATCH] WARNING: $1"; }

# 验证目录
if [ ! -d "$KSU_DIR/kernel" ]; then
    echo "ERROR: 找不到 $KSU_DIR/kernel 目录"
    exit 1
fi

log_info "目标目录: $(realpath $KSU_DIR)"
log_info "开始恢复 KPM 支持..."

# ============================================================
# Part 1: 创建 kernel/kpm/ 目录和源文件
# ============================================================
log_info "Part 1: 创建 KPM 内核源文件..."
mkdir -p "$KSU_DIR/kernel/kpm"

cat > "$KSU_DIR/kernel/kpm/kpm.h" << 'KPMH_EOF'
#ifndef __SUKISU_KPM_H
#define __SUKISU_KPM_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include "uapi/supercall.h"

int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2, unsigned long result_code);
int sukisu_is_kpm_control_code(unsigned long control_code);
int do_kpm(void __user *arg);

/* KPM Control Code */
#define CMD_KPM_CONTROL 1
#define CMD_KPM_CONTROL_MAX 10

#endif
KPMH_EOF

cat > "$KSU_DIR/kernel/kpm/compact.h" << 'CH_EOF'
#ifndef __SUKISU_KPM_COMPACT_H
#define __SUKISU_KPM_COMPACT_H
extern unsigned long sukisu_compact_find_symbol(const char *name);
#endif
CH_EOF

cat > "$KSU_DIR/kernel/kpm/compact.c" << 'CC_EOF'
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/set_memory.h>
#include "kpm.h"
#include "compact.h"
#include "policy/allowlist.h"
#include "manager/manager_identity.h"

static int sukisu_is_su_allow_uid(uid_t uid)
{
    return ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}
static int sukisu_get_ap_mod_exclude(uid_t uid) { return 0; }
static int sukisu_is_uid_should_umount(uid_t uid)
{
    return ksu_uid_should_umount(uid) ? 1 : 0;
}
static int sukisu_is_current_uid_manager(void) { return is_manager(); }

struct CompactAddressSymbol {
    const char *symbol_name;
    void *addr;
};

unsigned long sukisu_compact_find_symbol(const char *name);

static struct CompactAddressSymbol address_symbol[] = {
    { "kallsyms_lookup_name", &kallsyms_lookup_name },
    { "compact_find_symbol", &sukisu_compact_find_symbol },
    { "is_run_in_sukisu_ultra", (void *)1 },
    { "is_su_allow_uid", &sukisu_is_su_allow_uid },
    { "get_ap_mod_exclude", &sukisu_get_ap_mod_exclude },
    { "is_uid_should_umount", &sukisu_is_uid_should_umount },
    { "is_current_uid_manager", &sukisu_is_current_uid_manager },
};

unsigned long sukisu_compact_find_symbol(const char *name)
{
    int i;
    unsigned long addr;
    for (i = 0; i < (sizeof(address_symbol) / sizeof(struct CompactAddressSymbol)); i++) {
        struct CompactAddressSymbol *symbol = &address_symbol[i];
        if (strcmp(name, symbol->symbol_name) == 0)
            return (unsigned long)symbol->addr;
    }
    addr = kallsyms_lookup_name(name);
    if (addr) return addr;
    return 0;
}
EXPORT_SYMBOL(sukisu_compact_find_symbol);
CC_EOF

cat > "$KSU_DIR/kernel/kpm/kpm.c" << 'KPMC_EOF'
/* SPDX-License-Identifier: GPL-2.0-or-later */
/* KPM 内核模块加载器兼容实现 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/kernfs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <asm/elf.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/set_memory.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <asm/insn.h>
#include <linux/kprobes.h>
#include <linux/stacktrace.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) && defined(CONFIG_MODULES)
#include <linux/moduleloader.h>
#endif
#include "kpm.h"
#include "compact.h"
#include "compat/kernel_compat.h"
#include "uapi/supercall.h"

#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024

#ifndef NO_OPTIMIZE
#if defined(__GNUC__) && !defined(__clang__)
#define NO_OPTIMIZE __attribute__((optimize("O0")))
#elif defined(__clang__)
#define NO_OPTIMIZE __attribute__((optnone))
#else
#define NO_OPTIMIZE
#endif
#endif

noinline NO_OPTIMIZE void sukisu_kpm_load_module_path(const char *path, const char *args, void *ptr, int *result) {
    pr_info("kpm: Stub: sukisu_kpm_load_module_path path=%s\n", path);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

noinline NO_OPTIMIZE void sukisu_kpm_unload_module(const char *name, void *ptr, int *result) {
    pr_info("kpm: Stub: sukisu_kpm_unload_module name=%s\n", name);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline NO_OPTIMIZE void sukisu_kpm_num(int *result) {
    pr_info("kpm: Stub: sukisu_kpm_num\n");
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_num);

noinline NO_OPTIMIZE void sukisu_kpm_info(const char *name, char *buf, int bufferSize, int *size) {
    pr_info("kpm: Stub: sukisu_kpm_info name=%s\n", name);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_info);

noinline NO_OPTIMIZE void sukisu_kpm_list(void *out, int bufferSize, int *result) {
    pr_info("kpm: Stub: sukisu_kpm_list\n");
}
EXPORT_SYMBOL(sukisu_kpm_list);

noinline NO_OPTIMIZE void sukisu_kpm_control(const char *name, const char *args, long arg_len, int *result) {
    pr_info("kpm: Stub: sukisu_kpm_control\n");
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_control);

noinline NO_OPTIMIZE void sukisu_kpm_version(char *buf, int bufferSize) {
    pr_info("kpm: Stub: sukisu_kpm_version\n");
}
EXPORT_SYMBOL(sukisu_kpm_version);

noinline int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2, unsigned long result_code) {
    int res = -1;
    if (control_code == KSU_KPM_LOAD) {
        char path[256] = {0}, args[256] = {0};
        if (arg1 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(path))) goto invalid_arg;
        strncpy_from_user((char *)&path, (const char *)arg1, sizeof(path));
        if (arg2 != 0) {
            if (!ksu_access_ok(arg2, sizeof(args))) goto invalid_arg;
            strncpy_from_user((char *)&args, (const char *)arg2, sizeof(args));
        }
        sukisu_kpm_load_module_path(path, args, NULL, &res);
    } else if (control_code == KSU_KPM_UNLOAD) {
        char name[256] = {0};
        if (arg1 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(name))) goto invalid_arg;
        strncpy_from_user((char *)&name, (const char *)arg1, sizeof(name));
        sukisu_kpm_unload_module(name, NULL, &res);
    } else if (control_code == KSU_KPM_NUM) {
        sukisu_kpm_num(&res);
    } else if (control_code == KSU_KPM_INFO) {
        char name[256] = {0}, buf[256] = {0}; int size;
        if (arg1 == 0 || arg2 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(name))) goto invalid_arg;
        strncpy_from_user((char *)&name, (const char __user *)arg1, sizeof(name));
        sukisu_kpm_info(name, buf, sizeof(buf), &size);
        if (!ksu_access_ok(arg2, size)) goto invalid_arg;
        res = copy_to_user(arg2, &buf, size);
    } else if (control_code == KSU_KPM_LIST) {
        char buf[1024] = {0}; int len = (int)arg2;
        if (len <= 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg2, len)) goto invalid_arg;
        sukisu_kpm_list(buf, sizeof(buf), &res);
        if (res > len) { res = -ENOBUFS; goto exit; }
        if (copy_to_user(arg1, &buf, len) != 0) pr_info("kpm: Copy to user failed.");
    } else if (control_code == KSU_KPM_CONTROL) {
        char kpm_name[KPM_NAME_LEN] = {0}, kpm_args[KPM_ARGS_LEN] = {0};
        if (!ksu_access_ok(arg1, sizeof(kpm_name))) goto invalid_arg;
        if (!ksu_access_ok(arg2, sizeof(kpm_args))) goto invalid_arg;
        long name_len = strncpy_from_user(kpm_name, (const char __user *)arg1, sizeof(kpm_name));
        if (name_len <= 0) { res = -EINVAL; goto exit; }
        long arg_len = strncpy_from_user(kpm_args, (const char __user *)arg2, sizeof(kpm_args));
        sukisu_kpm_control(kpm_name, kpm_args, arg_len, &res);
    } else if (control_code == KSU_KPM_VERSION) {
        char buffer[256] = {0};
        sukisu_kpm_version(buffer, sizeof(buffer));
        unsigned int outlen = (unsigned int)arg2;
        int len = strlen(buffer);
        if (len >= (int)outlen) len = outlen - 1;
        res = copy_to_user(arg1, &buffer, len + 1);
    }
exit:
    if (copy_to_user(result_code, &res, sizeof(res)) != 0) pr_info("kpm: Copy result to user failed.");
    return 0;
invalid_arg:
    pr_err("kpm: invalid pointer! arg1: %px arg2: %px\n", (void *)arg1, (void *)arg2);
    res = -EFAULT;
    goto exit;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

int sukisu_is_kpm_control_code(unsigned long control_code) {
    return (control_code >= CMD_KPM_CONTROL && control_code <= CMD_KPM_CONTROL_MAX) ? 1 : 0;
}

int do_kpm(void __user *arg) {
    struct ksu_kpm_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) return -EFAULT;
    if (!ksu_access_ok(cmd.control_code, sizeof(int))) return -EFAULT;
    if (!ksu_access_ok(cmd.result_code, sizeof(int))) return -EFAULT;
    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2, cmd.result_code);
}
KPMC_EOF

cat > "$KSU_DIR/kernel/kpm/super_access.h" << 'SAH_EOF'
#ifndef __SUKISU_KPM_SUPER_ACCESS_H
#define __SUKISU_KPM_SUPER_ACCESS_H
unsigned long sukisu_super_access_get_member_offset(const char *struct_name, const char *member_name);
#endif
SAH_EOF

cat > "$KSU_DIR/kernel/kpm/super_access.c" << 'SAC_EOF'
#include <linux/export.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <../fs/mount.h>
#include "kpm.h"
#include "compact.h"

struct OffsetEntry {
    const char *struct_name;
    const char *member_name;
    size_t offset;
    size_t size;
};

static struct OffsetEntry offset_table[] = {
    { "task_struct", "files", offsetof(struct task_struct, files), sizeof(struct task_struct *) },
    { "task_struct", "mm", offsetof(struct task_struct, mm), sizeof(struct task_struct *) },
    { "task_struct", "pid", offsetof(struct task_struct, pid), sizeof(pid_t) },
    { "task_struct", "comm", offsetof(struct task_struct, comm), TASK_COMM_LEN },
    { "mount", "mnt_parent", offsetof(struct mount, mnt_parent), sizeof(struct mount *) },
};

unsigned long sukisu_super_access_get_member_offset(const char *struct_name, const char *member_name) {
    int i;
    for (i = 0; i < (int)(sizeof(offset_table) / sizeof(struct OffsetEntry)); i++) {
        if (strcmp(offset_table[i].struct_name, struct_name) == 0 &&
            strcmp(offset_table[i].member_name, member_name) == 0)
            return offset_table[i].offset;
    }
    return (unsigned long)-1;
}
EXPORT_SYMBOL(sukisu_super_access_get_member_offset);
SAC_EOF

log_info "KPM 源文件创建完成 (6个文件)"

# ============================================================
# Part 2: 修补 Kbuild
# ============================================================
log_info "Part 2: 修补 kernel/Kbuild..."
KBUILD="$KSU_DIR/kernel/Kbuild"

if ! grep -q "kpm/kpm.o" "$KBUILD"; then
    sed -i '/kernelsu-objs += supercall\/supercall\.o/a\
\
ifdef CONFIG_KPM\
kernelsu-objs += kpm/kpm.o\
kernelsu-objs += kpm/compact.o\
kernelsu-objs += kpm/super_access.o\
endif' "$KBUILD"
    log_info "  + KPM 编译目标已添加"
fi

if ! grep -q "KPM is enabled" "$KBUILD"; then
    sed -i '/# Keep a new line here/i\
# Check if KPM is enabled\
ifdef CONFIG_KPM\
  $(info -- KPM is enabled)\
else\
  $(info -- KPM is disabled)\
endif\
' "$KBUILD"
    log_info "  + KPM 构建信息已添加"
fi

# ============================================================
# Part 3: 修补 Kconfig (使用 Python 安全插入)
# ============================================================
log_info "Part 3: 修补 kernel/Kconfig..."
KCONFIG="$KSU_DIR/kernel/Kconfig"

if ! grep -q "config KPM" "$KCONFIG"; then
    python3 << 'PYEOF'
import sys
kconfig_path = sys.argv[1] if len(sys.argv) > 1 else "kernel/Kconfig"
with open(kconfig_path, 'r') as f:
    content = f.read()

kpm_block = """config KPM
\tbool "Enable SukiSU KPM"
\tdepends on KSU && 64BIT
\tselect KALLSYMS
\tselect KALLSYMS_ALL
\tdefault n
\thelp
\t  Enabling this option will activate the KPM feature.
\t  Requires CONFIG_KALLSYMS=y and CONFIG_KALLSYMS_ALL=y.

"""
target = 'choice\n\tprompt "KernelSU Hooking Method"'
if target in content:
    content = content.replace(target, kpm_block + target)
    with open(kconfig_path, 'w') as f:
        f.write(content)
    print("[KPM-PATCH] CONFIG_KPM inserted before choice block")
else:
    # Fallback: find the choice line
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'KernelSU Hooking Method' in line and 'prompt' in line:
            for j in range(i, -1, -1):
                if lines[j].strip() == 'choice':
                    lines.insert(j, kpm_block.rstrip('\n'))
                    break
            break
    with open(kconfig_path, 'w') as f:
        f.write('\n'.join(lines))
    print("[KPM-PATCH] CONFIG_KPM inserted (fallback method)")
PYEOF
    log_info "  + CONFIG_KPM 配置选项已添加"
fi

# ============================================================
# Part 4: 修补 uapi/supercall.h
# ============================================================
log_info "Part 4: 修补 uapi/supercall.h..."
SUPERCALL_H="$KSU_DIR/uapi/supercall.h"

if ! grep -q "KSU_IOCTL_ENABLE_KPM" "$SUPERCALL_H"; then
    sed -i 's%// 102 = ENABLE_KPM (KernelPatch Module),deprecated%DEFINE_KSU_UAPI_CONST(__u32, KSU_IOCTL_ENABLE_KPM, _IOC(_IOC_READ, '"'"'K'"'"', 102, 0))%' "$SUPERCALL_H"
    log_info "  + KSU_IOCTL_ENABLE_KPM 已恢复"
fi

if ! grep -q "KSU_IOCTL_KPM" "$SUPERCALL_H"; then
    sed -i 's%// 200 = MANAGE_KPM,deprecated%DEFINE_KSU_UAPI_CONST(__u32, KSU_IOCTL_KPM, _IOC(_IOC_READ | _IOC_WRITE, '"'"'K'"'"', 200, 0))%' "$SUPERCALL_H"
    log_info "  + KSU_IOCTL_KPM 已恢复"
fi

if ! grep -q "struct ksu_enable_kpm_cmd" "$SUPERCALL_H"; then
    sed -i '/struct ksu_hook_type_cmd {/,/};/{
        /};/a\
\
struct ksu_enable_kpm_cmd {\
    __u8 enabled;\
};
    }' "$SUPERCALL_H"
    log_info "  + ksu_enable_kpm_cmd 结构体已恢复"
fi

if ! grep -q "KSU_KPM_LOAD" "$SUPERCALL_H"; then
    sed -i '/struct ksu_get_managers_cmd/i\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_LOAD, 1)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_UNLOAD, 2)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_NUM, 3)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_LIST, 4)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_INFO, 5)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_CONTROL, 6)\
DEFINE_KSU_UAPI_CONST(__u8, KSU_KPM_VERSION, 7)\
\
struct ksu_kpm_cmd {\
    __u8 __user control_code;\
    __aligned_u64 __user arg1;\
    __aligned_u64 __user arg2;\
    __aligned_u64 __user result_code;\
} __attribute__((packed));\
' "$SUPERCALL_H"
    log_info "  + KPM 常量和 ksu_kpm_cmd 结构体已恢复"
fi

# ============================================================
# Part 5: 修补 dispatch.c
# ============================================================
log_info "Part 5: 修补 kernel/supercall/dispatch.c..."
DISPATCH_C="$KSU_DIR/kernel/supercall/dispatch.c"

if ! grep -q 'kpm/kpm.h' "$DISPATCH_C"; then
    sed -i '/#include "policy\/app_profile.h"/a\
#ifdef CONFIG_KPM\
#include "kpm/kpm.h"\
#endif' "$DISPATCH_C"
    log_info "  + KPM header include 已添加"
fi

if ! grep -q "do_enable_kpm" "$DISPATCH_C"; then
    sed -i '/^static int do_dynamic_manager/i\
static int do_enable_kpm(void __user *arg)\
{\
    struct ksu_enable_kpm_cmd cmd;\
    cmd.enabled = IS_ENABLED(CONFIG_KPM);\
    if (copy_to_user(arg, \&cmd, sizeof(cmd))) return -EFAULT;\
    return 0;\
}\
' "$DISPATCH_C"
    log_info "  + do_enable_kpm 函数已添加"
fi

# Add ioctl handlers using Python for reliability
python3 << 'PYEOF2'
import sys, re
dispatch_path = sys.argv[1] if len(sys.argv) > 1 else "kernel/supercall/dispatch.c"
with open(dispatch_path, 'r') as f:
    content = f.read()

# Add ENABLE_KPM handler
enable_kpm_entry = """    {
        .cmd = KSU_IOCTL_ENABLE_KPM,
        .name = "GET_ENABLE_KPM",
        .handler = do_enable_kpm,
        .perm_check = manager_or_root
    },"""
if "GET_ENABLE_KPM" not in content:
    # Find GET_HOOK_TYPE entry and add after it
    pattern = r'(        \.name = "GET_HOOK_TYPE",\n.*?        \.perm_check = manager_or_root\n    },)'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        content = content[:match.end()] + '\n' + enable_kpm_entry + content[match.end():]
        print("[KPM-PATCH] ENABLE_KPM handler added")

# Add KPM_OPERATION handler
kpm_entry = """#ifdef CONFIG_KPM
    {
        .cmd = KSU_IOCTL_KPM,
        .name = "KPM_OPERATION",
        .handler = do_kpm,
        .perm_check = manager_or_root
    },
#endif"""
if "KPM_OPERATION" not in content:
    pattern = r'(        \.name = "GET_KERNEL_PATCH_IMPLEMENT",\n.*?        \.perm_check = manager_or_root\n    },)'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        content = content[:match.end()] + '\n' + kpm_entry + content[match.end():]
        print("[KPM-PATCH] KPM_OPERATION handler added")

with open(dispatch_path, 'w') as f:
    f.write(content)
PYEOF2
    log_info "  + ioctl handlers已添加"

# ============================================================
# 修复 uapi 符号链接 (如果需要)
# ============================================================
if [ -L "$KSU_DIR/kernel/include/uapi" ]; then
    log_info "修复 uapi 符号链接..."
    rm "$KSU_DIR/kernel/include/uapi"
    cp -r "$KSU_DIR/uapi" "$KSU_DIR/kernel/include/uapi"
    log_info "  + uapi 符号链接已修复为实际目录"
fi

log_info "=========================================="
log_info "KPM 恢复补丁应用完成！"
log_info "编译时请确保添加 CONFIG_KPM=y 到 defconfig"
log_info "=========================================="
