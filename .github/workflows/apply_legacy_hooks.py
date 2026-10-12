#!/usr/bin/env python3
"""Apply KernelSU-Next legacy manual syscall hooks to FirmanBell/msm-4.4:legacy.

Based on the KernelSU Next non-GKI manual hook integration guide.
Fails closed when source lines differ from the reviewed kernel revision.
"""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str) -> None:
    body = path.read_text()
    count = body.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one exact anchor, found {count}: {old[:100]!r}")
    path.write_text(body.replace(old, new, 1))
    print(f"[OK] patched {path}")


def main(root: Path) -> None:
    if not (root / "arch/arm64/configs/platina_defconfig").is_file():
        raise RuntimeError("This script requires a kernel tree with platina_defconfig")
    targets = ["fs/exec.c", "fs/open.c", "fs/read_write.c", "fs/stat.c", "kernel/reboot.c"]
    for rel in targets:
        if "ksu_handle_" in (root / rel).read_text():
            raise RuntimeError(f"{rel} already contains KernelSU hooks: do not inject twice")

    p = root / "fs/exec.c"
    replace_once(p, "int do_execve(struct filename *filename,\n",
                 "#ifdef CONFIG_KSU\n"
                 "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
                 "\t\t\t      void *argv, void *envp, int *flags);\n"
                 "#endif\n\n"
                 "int do_execve(struct filename *filename,\n")
    replace_once(p,
                 "\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n"
                 "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);",
                 "\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
                 "#endif\n"
                 "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);")
    # After replacing the native call, the remaining identical return is compat_do_execve().
    replace_once(p,
                 "\t\t.ptr.compat = __envp,\n\t};\n"
                 "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);",
                 "\t\t.ptr.compat = __envp,\n\t};\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
                 "#endif\n"
                 "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);")

    p = root / "fs/open.c"
    replace_once(p,
                 "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)",
                 "#ifdef CONFIG_KSU\n"
                 "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
                 "\t\t\t      int *mode, int *flags);\n"
                 "#endif\n\n"
                 "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)")
    replace_once(p,
                 "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\tif (mode & ~S_IRWXO)",
                 "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
                 "#endif\n"
                 "\tif (mode & ~S_IRWXO)")

    p = root / "fs/read_write.c"
    replace_once(p,
                 "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)",
                 "#ifdef CONFIG_KSU\n"
                 "extern bool ksu_vfs_read_hook __read_mostly;\n"
                 "extern int ksu_handle_sys_read(unsigned int fd,\n"
                 "\t\t\t    char __user **buf_ptr, size_t *count_ptr);\n"
                 "#endif\n\n"
                 "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)")
    replace_once(p,
                 "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
                 "{\n\tstruct fd f = fdget_pos(fd);\n\tssize_t ret = -EBADF;",
                 "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n"
                 "{\n\tstruct fd f = fdget_pos(fd);\n\tssize_t ret = -EBADF;\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tif (unlikely(ksu_vfs_read_hook))\n"
                 "\t\tksu_handle_sys_read(fd, &buf, &count);\n"
                 "#endif")

    p = root / "fs/stat.c"
    replace_once(p,
                 "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,",
                 "#ifdef CONFIG_KSU\n"
                 "extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n"
                 "\t\t\t   int *flags);\n"
                 "#endif\n\n"
                 "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,")
    replace_once(p,
                 "\t\tstruct stat __user *, statbuf, int, flag)\n"
                 "{\n\tstruct kstat stat;\n\tint error;\n\n\terror = vfs_fstatat(dfd, filename, &stat, flag);",
                 "\t\tstruct stat __user *, statbuf, int, flag)\n"
                 "{\n\tstruct kstat stat;\n\tint error;\n\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tksu_handle_stat(&dfd, &filename, &flag);\n"
                 "#endif\n"
                 "\terror = vfs_fstatat(dfd, filename, &stat, flag);")

    p = root / "kernel/reboot.c"
    replace_once(p,
                 "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,",
                 "#ifdef CONFIG_KSU\n"
                 "extern int ksu_handle_sys_reboot(int magic1, int magic2,\n"
                 "\t\t\t      unsigned int cmd, void __user **arg);\n"
                 "#endif\n\n"
                 "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,")
    replace_once(p,
                 "\tchar buffer[256];\n\tint ret = 0;",
                 "\tchar buffer[256];\n\tint ret = 0;\n"
                 "#ifdef CONFIG_KSU\n"
                 "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
                 "#endif")

    for rel in targets:
        assert "ksu_handle_" in (root / rel).read_text(), f"Missing manual hook in {rel}"
    print("[OK] All five KernelSU Next legacy manual hook locations patched")


if __name__ == "__main__":
    try:
        main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd())
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
