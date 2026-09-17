#!/usr/bin/env python3
"""
apply_resukisu.py
Otomatis integrasi ReSukiSU ke kernel 4.14 Non-GKI (Samsung M51 / SM7150).

Yang dilakukan:
1. Tambah ReSukiSU sebagai git submodule di KernelSU/ (pakai setup.sh resmi resukisu).
2. Patch manual hooks wajib: stat, execve, faccessat, sys_reboot, setresuid, sys_read.
3. Export symbol SELinux (write_op, sel_handle_status_ops, dll) kalau CONFIG_KALLSYMS_ALL tidak dipakai.
4. Tambah CONFIG_KSU=y + CONFIG_KSU_MANUAL_HOOK=y ke semua defconfig yang match device.
5. Commit tiap tahap supaya history rapi & gampang di-rebase saat update ReSukiSU.

Pakai:
    python3 apply_resukisu.py --repo /path/to/kernel --defconfig m51_defconfig
    (jalankan di root clone kernel, branch sudah di-checkout)

Idempotent: aman dijalankan ulang, hook yang sudah ada di-skip.
"""
import argparse, re, subprocess, sys, glob, os

def sh(cmd, cwd, check=True):
    print(f"$ {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=cwd, text=True,
                        capture_output=True)
    if r.stdout: print(r.stdout.strip())
    if r.stderr: print(r.stderr.strip(), file=sys.stderr)
    if check and r.returncode != 0:
        sys.exit(f"[!] gagal: {cmd}")
    return r

def patch_file(path, patches, label):
    """patches: list of (marker_regex, insert_after_match_func) atau (old, new) literal."""
    if not os.path.isfile(path):
        print(f"[skip] {path} tidak ditemukan"); return False
    src = open(path, encoding="utf-8", errors="ignore").read()
    changed = False
    for check_str, old, new in patches:
        if check_str in src:
            continue  # sudah ter-hook
        if old not in src:
            print(f"[warn] pola tidak ketemu di {path} untuk hook '{label}' -> cek manual")
            continue
        src = src.replace(old, new, 1)
        changed = True
    if changed:
        open(path, "w", encoding="utf-8").write(src)
        print(f"[ok] hook '{label}' -> {path}")
    return changed

def add_submodule(repo):
    ksu_dir = os.path.join(repo, "KernelSU")
    if os.path.isdir(ksu_dir):
        print("[skip] KernelSU/ sudah ada"); return
    sh('bash -c \'curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash -s main\'', repo)
    # setup.sh biasanya add sebagai folder biasa; convert jadi submodule asli
    if os.path.isdir(ksu_dir) and not os.path.isfile(os.path.join(repo, ".gitmodules")):
        sh("git rm -r --cached KernelSU", repo, check=False)
        sh("rm -rf KernelSU", repo)
        sh("git submodule add https://github.com/ReSukiSU/ReSukiSU.git KernelSU", repo)
        sh("git submodule update --init --recursive", repo)
    sh('git add .gitmodules KernelSU && git commit -m "chore: add ReSukiSU as submodule"', repo, check=False)

def hook_stat(repo):
    f = os.path.join(repo, "fs/stat.c")
    patches = [
        ("ksu_handle_newfstat_ret",
         "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n\t\tstruct stat __user *, statbuf, int, flag)\n{",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n__attribute__((hot))\nextern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\nextern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);\n#endif\n\nSYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n\t\tstruct stat __user *, statbuf, int, flag)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tksu_handle_stat(&dfd, &filename, &flag);\n#endif"),
        ("ksu_handle_newfstat_ret(&fd",
         "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{",
         "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tksu_handle_newfstat_ret(&fd, &statbuf);\n#endif"),
    ]
    patch_file(f, patches, "stat")

def hook_faccessat(repo):
    f = os.path.join(repo, "fs/open.c")
    patches = [
        ("ksu_handle_faccessat",
         "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n__attribute__((hot))\nextern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode, int *flags);\n#endif\n\nSYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n#endif"),
    ]
    patch_file(f, patches, "faccessat")

def hook_execve(repo):
    # kernel 4.14 pakai fs/exec.c dengan do_execveat_common(struct filename*)
    f = os.path.join(repo, "fs/exec.c")
    patches = [
        ("ksu_handle_execveat",
         "static int do_execveat_common(int fd, struct filename *filename,\n\t\t\t      struct user_arg_ptr argv,\n\t\t\t      struct user_arg_ptr envp,\n\t\t\t      int flags)\n{\n\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);\n}",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\n__attribute__((hot))\nextern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);\n__attribute__((hot))\nextern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags, int *retval);\n#endif\n\nstatic int do_execveat_common(int fd, struct filename *filename,\n\t\t\t      struct user_arg_ptr argv,\n\t\t\t      struct user_arg_ptr envp,\n\t\t\t      int flags)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tint retval;\n\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);\n\tretval = __do_execve_file(fd, filename, argv, envp, flags, NULL);\n\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);\n\treturn retval;\n#else\n\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);\n#endif\n}"),
    ]
    ok = patch_file(f, patches, "execve(do_execveat_common)")
    if not ok:
        print("[!] execve hook TIDAK otomatis ke-apply — signature do_execveat_common beda di kernel ini.")
        print("    Cek manual: https://resukisu.org/guide/manual-integrate.html#execve-hooks")

def hook_reboot(repo):
    for f in (os.path.join(repo, "kernel/reboot.c"), os.path.join(repo, "kernel/sys.c")):
        patches = [
            ("ksu_handle_sys_reboot",
             "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n\t\tvoid __user *, arg)\n{",
             "#ifdef CONFIG_KSU_MANUAL_HOOK\nextern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n#endif\n\nSYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n\t\tvoid __user *, arg)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n#endif"),
        ]
        patch_file(f, patches, "sys_reboot")

def hook_setresuid(repo):
    f = os.path.join(repo, "kernel/sys.c")
    patches = [
        ("ksu_handle_setresuid",
         "long __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)\n{",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\nextern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n#endif\n\nlong __sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\t(void)ksu_handle_setresuid(ruid, euid, suid);\n#endif"),
        ("ksu_handle_setresuid",
         "SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n{",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\nextern int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);\n#endif\n\nSYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\t(void)ksu_handle_setresuid(ruid, euid, suid);\n#endif"),
    ]
    patch_file(f, patches, "setresuid")

def hook_sys_read(repo):
    f = os.path.join(repo, "fs/read_write.c")
    patches = [
        ("ksu_handle_sys_read",
         "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n{",
         "#ifdef CONFIG_KSU_MANUAL_HOOK\nextern bool ksu_init_rc_hook __read_mostly;\nextern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr, size_t *count_ptr);\n#endif\n\nSYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n{\n#ifdef CONFIG_KSU_MANUAL_HOOK\n\tif (ksu_init_rc_hook)\n\t\tksu_handle_sys_read(fd, &buf, &count);\n#endif"),
    ]
    patch_file(f, patches, "sys_read")

def selinux_exports(repo):
    f1 = os.path.join(repo, "security/selinux/selinuxfs.c")
    patch_file(f1, [
        ("ssize_t (*write_op[])",
         "static ssize_t (*write_op[])(struct file *, char *, size_t) = {",
         "ssize_t (*write_op[])(struct file *, char *, size_t) = {"),
        ("const struct file_operations sel_handle_status_ops",
         "static const struct file_operations sel_handle_status_ops = {",
         "const struct file_operations sel_handle_status_ops = {"),
    ], "selinux write_op/status_ops export")

    f2 = os.path.join(repo, "security/selinux/ss/status.c")
    patch_file(f2, [
        ("struct page *selinux_status_page;",
         "static struct page *selinux_status_page;\nstatic DEFINE_MUTEX(selinux_status_lock);",
         "struct page *selinux_status_page;\nDEFINE_MUTEX(selinux_status_lock);"),
    ], "selinux_status_page/lock export (4.17-)")

    f3 = os.path.join(repo, "security/selinux/ss/services.c")
    patch_file(f3, [
        ("DEFINE_RWLOCK(policy_rwlock);",
         "static DEFINE_RWLOCK(policy_rwlock);",
         "DEFINE_RWLOCK(policy_rwlock);"),
    ], "policy_rwlock export (4.17-)")

def patch_defconfig(repo, name_hint):
    cfgs = glob.glob(os.path.join(repo, "arch/arm64/configs/**/*defconfig*"), recursive=True)
    matched = [c for c in cfgs if name_hint.lower() in os.path.basename(c).lower()] or cfgs
    if not matched:
        print("[!] tidak ada defconfig ditemukan, tambahkan manual: CONFIG_KSU=y / CONFIG_KSU_MANUAL_HOOK=y")
        return
    block = "\n# ReSukiSU\nCONFIG_KSU=y\nCONFIG_KSU_MANUAL_HOOK=y\n"
    for c in matched:
        content = open(c, encoding="utf-8", errors="ignore").read()
        if "CONFIG_KSU=y" in content:
            print(f"[skip] {c} sudah ada CONFIG_KSU"); continue
        open(c, "a", encoding="utf-8").write(block)
        print(f"[ok] defconfig -> {c}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--defconfig", default="m51", help="substring nama defconfig target device")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo)

    add_submodule(repo)
    hook_stat(repo)
    hook_execve(repo)
    hook_faccessat(repo)
    hook_reboot(repo)
    hook_setresuid(repo)
    hook_sys_read(repo)
    selinux_exports(repo)
    patch_defconfig(repo, args.defconfig)

    sh("git add -A", repo, check=False)
    sh('git commit -m "feat: integrate ReSukiSU manual hooks (auto)"', repo, check=False)
    print("\n[DONE] Review hasil patch (git diff / git log) sebelum push & build.")
    print("Hook yang gagal auto-match akan muncul sebagai [warn]/[!] di atas -> patch manual sesuai baris tsb.")

if __name__ == "__main__":
    main()
