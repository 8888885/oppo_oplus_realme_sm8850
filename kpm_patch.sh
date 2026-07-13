#!/bin/bash
# =============================================================
# KPM 恢复补丁 - 在最新 ReSukiSU 上游代码上重新启用 KPM 支持
# 
# 背景: ReSukiSU 上游在 commit faac3098 (2026-06-06) 中移除了
#       KPM (KernelPatch Module) 支持。本脚本将 KPM 代码恢复
#       到最新上游版本中。
#
# 用法: bash kpm_patch.sh [KernelSU目录]
#       默认目录为当前工作目录下的 KernelSU
# =============================================================

set -e

KSU_DIR="${1:-kernel_workspace/KernelSU}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[KPM-PATCH]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[KPM-PATCH]${NC} $1"; }
log_error() { echo -e "${RED}[KPM-PATCH]${NC} $1"; }

# 验证目录
if [ ! -d "$KSU_DIR/kernel" ]; then
    log_error "找不到 $KSU_DIR/kernel 目录"
    log_error "请确保 setup.sh 已经成功执行"
    exit 1
fi

log_info "目标目录: $(realpath $KSU_DIR)"
log_info "开始恢复 KPM 支持..."

# ============================================================
# Part 1: 创建 kernel/kpm/ 目录和源文件
# ============================================================
log_info "Part 1: 创建 KPM 内核源文件..."

mkdir -p "$KSU_DIR/kernel/kpm"

# --- kpm.h ---
cat > "$KSU_DIR/kernel/kpm/kpm.h" << 'EOF'
#ifndef __SUKISU_KPM_H
#define __SUKISU_KPM_H

#include <linux/types.h>
#include <linux/ioctl.h>

int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2, unsigned long result_code);
int sukisu_is_kpm_control_code(unsigned long control_code);
int do_kpm(void __user *arg);

/* KPM Control Code */
#define CMD_KPM_CONTROL 1
#define CMD_KPM_CONTROL_MAX 10

#endif
EOF

# --- compact.h ---
cat > "$KSU_DIR/kernel/kpm/compact.h" << 'EOF'
#ifndef __SUKISU_KPM_COMPACT_H
#define __SUKISU_KPM_COMPACT_H

extern unsigned long sukisu_compact_find_symbol(const char *name);

#endif
EOF

# --- compact.c ---
cat > "$KSU_DIR/kernel/kpm/compact.c" << 'EOF'
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

static int sukisu_get_ap_mod_exclude(uid_t uid)
{
    return 0; /* Not supported */
}

static int sukisu_is_uid_should_umount(uid_t uid)
{
    return ksu_uid_should_umount(uid) ? 1 : 0;
}

static int sukisu_is_current_uid_manager(void)
{
    return is_manager();
}

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
    if (addr)
        return addr;

    return 0;
}
EXPORT_SYMBOL(sukisu_compact_find_symbol);
EOF

# --- kpm.c ---
cat > "$KSU_DIR/kernel/kpm/kpm.c" << 'EOF'
/* SPDX-License-Identifier: GPL-2.0-or-later */
/* KPM 内核模块加载器兼容实现 - 适配最新 ReSukiSU */

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

noinline NO_OPTIMIZE void sukisu_kpm_load_module_path(const char *path, const char *args, void *ptr, int *result)
{
    pr_info("kpm: Stub function called (sukisu_kpm_load_module_path). path=%s args=%s ptr=%p\n", path, args, ptr);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_load_module_path);

noinline NO_OPTIMIZE void sukisu_kpm_unload_module(const char *name, void *ptr, int *result)
{
    pr_info("kpm: Stub function called (sukisu_kpm_unload_module). name=%s ptr=%p\n", name, ptr);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_unload_module);

noinline NO_OPTIMIZE void sukisu_kpm_num(int *result)
{
    pr_info("kpm: Stub function called (sukisu_kpm_num).\n");
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_num);

noinline NO_OPTIMIZE void sukisu_kpm_info(const char *name, char *buf, int bufferSize, int *size)
{
    pr_info("kpm: Stub function called (sukisu_kpm_info). name=%s buffer=%p\n", name, buf);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_info);

noinline NO_OPTIMIZE void sukisu_kpm_list(void *out, int bufferSize, int *result)
{
    pr_info("kpm: Stub function called (sukisu_kpm_list). buffer=%p size=%d\n", out, bufferSize);
}
EXPORT_SYMBOL(sukisu_kpm_list);

noinline NO_OPTIMIZE void sukisu_kpm_control(const char *name, const char *args, long arg_len, int *result)
{
    pr_info("kpm: Stub function called (sukisu_kpm_control). name=%p args=%p arg_len=%ld\n", name, args, arg_len);
    __asm__ volatile("nop");
}
EXPORT_SYMBOL(sukisu_kpm_control);

noinline NO_OPTIMIZE void sukisu_kpm_version(char *buf, int bufferSize)
{
    pr_info("kpm: Stub function called (sukisu_kpm_version). buffer=%p\n", buf);
}
EXPORT_SYMBOL(sukisu_kpm_version);

noinline int sukisu_handle_kpm(unsigned long control_code, unsigned long arg1, unsigned long arg2,
                               unsigned long result_code)
{
    int res = -1;
    if (control_code == KSU_KPM_LOAD) {
        char kernel_load_path[256] = { 0 };
        char kernel_args_buffer[256] = { 0 };
        if (arg1 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(kernel_load_path))) goto invalid_arg;
        strncpy_from_user((char *)&kernel_load_path, (const char *)arg1, sizeof(kernel_load_path));
        if (arg2 != 0) {
            if (!ksu_access_ok(arg2, sizeof(kernel_args_buffer))) goto invalid_arg;
            strncpy_from_user((char *)&kernel_args_buffer, (const char *)arg2, sizeof(kernel_args_buffer));
        }
        sukisu_kpm_load_module_path((const char *)&kernel_load_path, (const char *)&kernel_args_buffer, NULL, &res);
    } else if (control_code == KSU_KPM_UNLOAD) {
        char kernel_name_buffer[256] = { 0 };
        if (arg1 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(kernel_name_buffer))) goto invalid_arg;
        strncpy_from_user((char *)&kernel_name_buffer, (const char *)arg1, sizeof(kernel_name_buffer));
        sukisu_kpm_unload_module((const char *)&kernel_name_buffer, NULL, &res);
    } else if (control_code == KSU_KPM_NUM) {
        sukisu_kpm_num(&res);
    } else if (control_code == KSU_KPM_INFO) {
        char kernel_name_buffer[256] = { 0 };
        char buf[256] = { 0 };
        int size;
        if (arg1 == 0 || arg2 == 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg1, sizeof(kernel_name_buffer))) goto invalid_arg;
        strncpy_from_user((char *)&kernel_name_buffer, (const char __user *)arg1, sizeof(kernel_name_buffer));
        sukisu_kpm_info((const char *)&kernel_name_buffer, (char *)&buf, sizeof(buf), &size);
        if (!ksu_access_ok(arg2, size)) goto invalid_arg;
        res = copy_to_user(arg2, &buf, size);
    } else if (control_code == KSU_KPM_LIST) {
        char buf[1024] = { 0 };
        int len = (int)arg2;
        if (len <= 0) { res = -EINVAL; goto exit; }
        if (!ksu_access_ok(arg2, len)) goto invalid_arg;
        sukisu_kpm_list((char *)&buf, sizeof(buf), &res);
        if (res > len) { res = -ENOBUFS; goto exit; }
        if (copy_to_user(arg1, &buf, len) != 0) pr_info("kpm: Copy to user failed.");
    } else if (control_code == KSU_KPM_CONTROL) {
        char kpm_name[KPM_NAME_LEN] = { 0 };
        char kpm_args[KPM_ARGS_LEN] = { 0 };
        if (!ksu_access_ok(arg1, sizeof(kpm_name))) goto invalid_arg;
        if (!ksu_access_ok(arg2, sizeof(kpm_args))) goto invalid_arg;
        long name_len = strncpy_from_user((char *)&kpm_name, (const char __user *)arg1, sizeof(kpm_name));
        if (name_len <= 0) { res = -EINVAL; goto exit; }
        long arg_len = strncpy_from_user((char *)&kpm_args, (const char __user *)arg2, sizeof(kpm_args));
        sukisu_kpm_control((const char *)&kpm_name, (const char *)&kpm_args, arg_len, &res);
    } else if (control_code == KSU_KPM_VERSION) {
        char buffer[256] = { 0 };
        sukisu_kpm_version((char *)&buffer, sizeof(buffer));
        unsigned int outlen = (unsigned int)arg2;
        int len = strlen(buffer);
        if (len >= outlen) len = outlen - 1;
        res = copy_to_user(arg1, &buffer, len + 1);
    }

exit:
    if (copy_to_user(result_code, &res, sizeof(res)) != 0)
        pr_info("kpm: Copy to user failed.");
    return 0;
invalid_arg:
    pr_err("kpm: invalid pointer detected! arg1: %px arg2: %px\n", (void *)arg1, (void *)arg2);
    res = -EFAULT;
    goto exit;
}
EXPORT_SYMBOL(sukisu_handle_kpm);

int sukisu_is_kpm_control_code(unsigned long control_code)
{
    return (control_code >= CMD_KPM_CONTROL && control_code <= CMD_KPM_CONTROL_MAX) ? 1 : 0;
}

int do_kpm(void __user *arg)
{
    struct ksu_kpm_cmd cmd;
    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("kpm: copy_from_user failed\n");
        return -EFAULT;
    }
    if (!ksu_access_ok(cmd.control_code, sizeof(int))) {
        pr_err("kpm: invalid control_code pointer %px\n", (void *)cmd.control_code);
        return -EFAULT;
    }
    if (!ksu_access_ok(cmd.result_code, sizeof(int))) {
        pr_err("kpm: invalid result_code pointer %px\n", (void *)cmd.result_code);
        return -EFAULT;
    }
    return sukisu_handle_kpm(cmd.control_code, cmd.arg1, cmd.arg2, cmd.result_code);
}
EOF

# --- super_access.h ---
cat > "$KSU_DIR/kernel/kpm/super_access.h" << 'EOF'
#ifndef __SUKISU_KPM_SUPER_ACCESS_H
#define __SUKISU_KPM_SUPER_ACCESS_H

unsigned long sukisu_super_access_get_member_offset(const char *struct_name, const char *member_name);

#endif
EOF

# --- super_access.c ---
cat > "$KSU_DIR/kernel/kpm/super_access.c" << 'EOF'
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
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/mount.h>
#include <linux/kprobes.h>
#include <linux/mm_types.h>
#include <linux/netlink.h>
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

unsigned long sukisu_super_access_get_member_offset(const char *struct_name, const char *member_name)
{
    int i;
    for (i = 0; i < (sizeof(offset_table) / sizeof(struct OffsetEntry)); i++) {
        if (strcmp(offset_table[i].struct_name, struct_name) == 0 &&
            strcmp(offset_table[i].member_name, member_name) == 0) {
            return offset_table[i].offset;
        }
    }
    return (unsigned long)-1;
}
EXPORT_SYMBOL(sukisu_super_access_get_member_offset);
EOF

log_info "KPM 源文件创建完成 (6个文件)"

# ============================================================
# Part 2: 修补 Kbuild
# ============================================================
log_info "Part 2: 修补 kernel/Kbuild..."

KBUILD="$KSU_DIR/kernel/Kbuild"

# 添加 KPM 目标文件 (在 supercall/supercall.o 之后)
if ! grep -q "kpm/kpm.o" "$KBUILD"; then
    sed -i '/kernelsu-objs += supercall\/supercall\.o/a\
\
ifdef CONFIG_KPM\
kernelsu-objs += kpm/kpm.o\
kernelsu-objs += kpm/compact.o\
kernelsu-objs += kpm/super_access.o\
endif' "$KBUILD"
    log_info "  + KPM 编译目标已添加"
else
    log_warn "  (跳过) KPM 编译目标已存在"
fi

# 添加 KPM 构建信息
if ! grep -q "KPM is enabled" "$KBUILD"; then
    sed -i '/# Keep a new line here/i\
# Check if KPM is enabled\
ifdef CONFIG_KPM\
  $(info -- KPM is enabled)\
  $(info -- WARNING, This feature is unstable!!! You are WARNED!!!)\
else\
  $(info -- KPM is disabled)\
endif\
' "$KBUILD"
    log_info "  + KPM 构建信息已添加"
fi

# ============================================================
# Part 3: 修补 Kconfig
# ============================================================
log_info "Part 3: 修补 kernel/Kconfig..."

KCONFIG="$KSU_DIR/kernel/Kconfig"

if ! grep -q "config KPM" "$KCONFIG"; then
    # 在 "KernelSU Hooking Method" choice 之前插入
    sed -i '/prompt "KernelSU Hooking Method"/i\
config KPM\
\tbool "Enable SukiSU KPM"\
\tdepends on KSU \&\& 64BIT\
\tselect KALLSYMS\
\tselect KALLSYMS_ALL\
\tdefault n\
\thelp\
\t  Enabling this option will activate the KPM feature of SukiSU.\
\t  This option is suitable for scenarios where you need to force KPM to be enabled.\
\t  but it may affect system stability.\
' "$KCONFIG"
    log_info "  + CONFIG_KPM 配置选项已添加"
else
    log_warn "  (跳过) CONFIG_KPM 已存在"
fi

# ============================================================
# Part 4: 修补 uapi/supercall.h
# ============================================================
log_info "Part 4: 修补 uapi/supercall.h..."

SUPERCALL_H="$KSU_DIR/uapi/supercall.h"

# 4a. 恢复 KSU_IOCTL_ENABLE_KPM 定义
if ! grep -q "KSU_IOCTL_ENABLE_KPM" "$SUPERCALL_H"; then
    sed -i 's%// 102 = ENABLE_KPM (KernelPatch Module),deprecated%DEFINE_KSU_UAPI_CONST(__u32, KSU_IOCTL_ENABLE_KPM, _IOC(_IOC_READ, '"'"'K'"'"', 102, 0))%' "$SUPERCALL_H"
    log_info "  + KSU_IOCTL_ENABLE_KPM 已恢复"
fi

# 4b. 恢复 KSU_IOCTL_KPM 定义
if ! grep -q "KSU_IOCTL_KPM" "$SUPERCALL_H"; then
    sed -i 's%// 200 = MANAGE_KPM,deprecated%DEFINE_KSU_UAPI_CONST(__u32, KSU_IOCTL_KPM, _IOC(_IOC_READ | _IOC_WRITE, '"'"'K'"'"', 200, 0))%' "$SUPERCALL_H"
    log_info "  + KSU_IOCTL_KPM 已恢复"
fi

# 4c. 恢复 ksu_enable_kpm_cmd 结构体
if ! grep -q "struct ksu_enable_kpm_cmd" "$SUPERCALL_H"; then
    sed -i '/struct ksu_hook_type_cmd {/,/};/{
        /};/a\
\
struct ksu_enable_kpm_cmd {\
    __u8 enabled; /* Output: true if KPM is enabled */\
};
    }' "$SUPERCALL_H"
    log_info "  + ksu_enable_kpm_cmd 结构体已恢复"
fi

# 4d. 恢复 KPM 常量和 ksu_kpm_cmd 结构体
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
# Part 5: 修补 kernel/supercall/dispatch.c
# ============================================================
log_info "Part 5: 修补 kernel/supercall/dispatch.c..."

DISPATCH_C="$KSU_DIR/kernel/supercall/dispatch.c"

# 5a. 添加 KPM header include
if ! grep -q 'kpm/kpm.h' "$DISPATCH_C"; then
    sed -i '/#include "policy\/app_profile.h"/a\
#ifdef CONFIG_KPM\
#include "kpm/kpm.h"\
#endif' "$DISPATCH_C"
    log_info "  + KPM header include 已添加"
fi

# 5b. 添加 do_enable_kpm 函数
if ! grep -q "do_enable_kpm" "$DISPATCH_C"; then
    # 找到 do_dynamic_manager 函数定义并在此之前插入
    sed -i '/^static int do_dynamic_manager/i\
// 102. ENABLE_KPM - Check if KPM is enabled\
static int do_enable_kpm(void __user *arg)\
{\
    struct ksu_enable_kpm_cmd cmd;\
    cmd.enabled = IS_ENABLED(CONFIG_KPM);\
    if (copy_to_user(arg, \&cmd, sizeof(cmd))) {\
        pr_err("enable_kpm: copy_to_user failed\\n");\
        return -EFAULT;\
    }\
    return 0;\
}\
' "$DISPATCH_C"
    log_info "  + do_enable_kpm 函数已添加"
fi

# 5c. 添加 ENABLE_KPM ioctl handler 到 handler 表
if ! grep -q "GET_ENABLE_KPM" "$DISPATCH_C"; then
    sed -i '/\.name = "GET_HOOK_TYPE"/,/\.perm_check = manager_or_root/{
        /\.perm_check = manager_or_root/a\
    },\
    {\
        .cmd = KSU_IOCTL_ENABLE_KPM,\
        .name = "GET_ENABLE_KPM",\
        .handler = do_enable_kpm,\
        .perm_check = manager_or_root
    }' "$DISPATCH_C"
    log_info "  + ENABLE_KPM ioctl handler 已添加"
fi

# 5d. 添加 KPM_OPERATION ioctl handler
if ! grep -q "KPM_OPERATION" "$DISPATCH_C"; then
    sed -i '/\.name = "GET_KERNEL_PATCH_IMPLEMENT"/,/\.perm_check = manager_or_root/{
        /\.perm_check = manager_or_root/a\
    },\
#ifdef CONFIG_KPM\
    {\
        .cmd = KSU_IOCTL_KPM,\
        .name = "KPM_OPERATION",\
        .handler = do_kpm,\
        .perm_check = manager_or_root\
    },\
#endif
    }' "$DISPATCH_C"
    log_info "  + KPM_OPERATION ioctl handler 已添加"
fi

# ============================================================
# 验证
# ============================================================
echo ""
log_info "========== 验证结果 =========="
log_info "KPM 源文件:    $(ls "$KSU_DIR/kernel/kpm/" | wc -l) 个文件"
log_info "Kbuild KPM:    $(grep -c 'kpm/' "$KBUILD" 2>/dev/null || echo 0) 处引用"
log_info "Kconfig KPM:   $(grep -c 'KPM' "$KCONFIG" 2>/dev/null || echo 0) 处引用"
log_info "supercall.h:   KSU_IOCTL_ENABLE_KPM=$(grep -c 'KSU_IOCTL_ENABLE_KPM' "$SUPERCALL_H") KSU_IOCTL_KPM=$(grep -c 'KSU_IOCTL_KPM' "$SUPERCALL_H") KSU_KPM_LOAD=$(grep -c 'KSU_KPM_LOAD' "$SUPERCALL_H")"
log_info "dispatch.c:    do_enable_kpm=$(grep -c 'do_enable_kpm' "$DISPATCH_C") KPM_OPERATION=$(grep -c 'KPM_OPERATION' "$DISPATCH_C")"
log_info "================================"
log_info "KPM 恢复补丁应用完成！"
log_info "编译时请确保添加 CONFIG_KPM=y 到 defconfig"
