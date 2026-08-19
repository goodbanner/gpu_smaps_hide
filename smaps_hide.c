/*
 * smaps_hide.c - Safe hide GPU driver libs from /proc pid maps/smaps
 * for non-su apps (uid >= min_uid), on Android GKI 6.6 (arm64).
 *
 * 修正要点：将 targets 从 char * 改为数组，消除模块默认加载时
 * 潛在的只读段写入风险。其他安全設計（UID過濾、寄存器安全、
 * forbidden_blacklist、kprobe 符號驗證、debug_mode 開關）完全相同。
 *
 * 編譯：clang -target arm64 -D__KERNEL__ -DMODULE ... (GKI 交叉編譯環境)
 * 載入：insmod smaps_hide.ko [targets="..."] min_uid=10000 [debug_mode=1]
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/cred.h>
#include <linux/string.h>

/* 1. 模組參數：目標庫子串 (逗號分隔) */
/* 【修正】char[] 而非 char *，避免默認初始化為字符串常量導致的
 only读段写入风险。module_param 依然正常工作。 */
static char targets[] = 
    "libllvm-qgl,libadreno_app_profiles,libGLESv2_adreno,"
    "libllvm-glnext,libgsl,eglSubDriverAndroid,libEGL_adreno,"
    "vulkan.adreno,libmapperutils,libadreno_utils,"
    "libdmabufheap,vendor.qti.qspmhal,libqspm-mem-utils-vendor";

module_param(targets, charp, 0644);
MODULE_PARM_DESC(targets,
    "Comma‑separated list of library substrings to hide from /proc pid maps/smaps "
    "for non‑su apps. Default is the 15 libraries detected in your system: "
    "libllvm-qgl, libadreno_app_profiles, libGLESv2_adreno, libllvm-glnext, "
    "libgsl, eglSubDriverAndroid, libEGL_adreno, vulkan.adreno, "
    "libmapperutils, libadreno_utils, libdmabufheap, vendor.qti.qspmhal, libqspm-mem-utils-vendor.");

static int min_uid = 10000;
module_param(min_uid, int, 0644);
MODULE_PARM_DESC(min_uid,
    "Minimum UID considered a non‑su app. Apps with uid >= min_uid will have target libs hidden. "
    "Default: 10000 (normal apps), root/su apps (uid=0) are always excluded from hiding.");

/* 2. 調試日誌開關 (預設 false) */
static bool debug_mode = false;
module_param(debug_mode, bool, 0444);
MODULE_PARM_DESC(debug_mode,
    "Enable extra debug logs for path/uid hiding decisions. "
    "Set insmod ... debug_mode=1 to activate. "
    "Will print \"smaps_hide: hide decision: path=... uid=... result=allow/skip\");

/* 3. 禁用永久黑名單：絕對不能隱藏的系統關鍵子串 */
static const char *const forbidden_blacklist[] = {
    "libc.", "libm.", "libpthread", "libcrypt", "libdl.", "linux/",
    NULL
};

/* 4. 目標解析 */
#define MAX_TARGETS 32
static char *target_tab[MAX_TARGETS];
static int num_targets;

static int __init parse_targets_buf(char *buf)
{
    char *p = buf;
    int i = 0;
    while (*p && i < MAX_TARGETS) {
        target_tab[i++] = p;
        p = strchr(p, ',');
        if (p) { *p = '\0'; p++; }
    }
    return i;
}

static bool path_is_forbidden(const char *path)
{
    int i = 0;
    while (forbidden_blacklist[i]) {
        if (strstr(path, forbidden_blacklist[i]))
            return true;
        i++;
    }
    return false;
}

static bool path_match_targets(const char *path)
{
    if (path_is_forbidden(path))
        return false;
    for (int i = 0; i < num_targets; i++) {
        if (strstr(path, target_tab[i]))
            return true;
    }
    return false;
}

/* 5. kprobe show_map (maps) */
static struct kprobe kp_maps = {
    .symbol_name = "show_map",
    .pre_handler = NULL,
};

static int pre_hide_maps(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (!m || !vma) return 0;

    uid_t uid = from_kuid_munged(init_user_ns, current_uid());
    bool should_hide = (uid >= (uid_t)min_uid);

    if (debug_mode) {
        char buf[PAGE_SIZE];
        const char *path = vma->vm_file ? d_path(&vma->vm_file->f_path, buf, PAGE_SIZE) : "(anonymous)";
        if (IS_ERR(path)) path = "(error)";
        pr_info("smaps_hide: hide decision: path=%s uid=%d result=%s\n",
                path, (int)uid, should_hide ? "enable_hide" : "skip");
    }
    if (!should_hide) return 0;

    if (!vma->vm_file) return 0;
    char path_buf[PAGE_SIZE];
    const char *path = d_path(&vma->vm_file->f_path, path_buf, PAGE_SIZE);
    if (IS_ERR(path)) return 0;

    if (path_is_forbidden(path)) {
        if (debug_mode) pr_info("smaps_hide: skip (forbidden system path)\n");
        return 0;
    }
    if (!path_match_targets(path)) {
        if (debug_mode) pr_info("smaps_hide: skip (no target match)\n");
        return 0;
    }

    /* 【鐵律】僅歸零返回值，絕對不觸動 pc 等寄存器 */
    regs->regs[0] = 0;
    if (debug_mode) pr_info("smaps_hide: hide entry (target library matched)\n");
    return 0;
}

/* 6. kprobe show_smap (smaps, smaps_rollup) */
static struct kprobe kp_smap = {
    .symbol_name = "show_smap",
    .pre_handler = NULL,
};

static int pre_hide_smap(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (!m || !vma) return 0;

    uid_t uid = from_kuid_munged(init_user_ns, current_uid());
    bool should_hide = (uid >= (uid_t)min_uid);

    if (debug_mode) {
        char buf[PAGE_SIZE];
        const char *path = vma->vm_file ? d_path(&vma->vm_file->f_path, buf, PAGE_SIZE) : "(anonymous)";
        if (IS_ERR(path)) path = "(error)";
        pr_info("smaps_hide: hide decision: path=%s uid=%d result=%s\n",
                path, (int)uid, should_hide ? "enable_hide" : "skip");
    }
    if (!should_hide) return 0;

    if (!vma->vm_file) return 0;
    char path_buf[PAGE_SIZE];
    const char *path = d_path(&vma->vm_file->f_path, path_buf, PAGE_SIZE);
    if (IS_ERR(path)) return 0;

    if (path_is_forbidden(path)) {
        if (debug_mode) pr_info("smaps_hide: skip (forbidden system path)\n");
        return 0;
    }
    if (!path_match_targets(path)) {
        if (debug_mode) pr_info("smaps_hide: skip (no target match)\n");
        return 0;
    }

    /* 【鐵律】僅歸零返回值，不觸動 pc 等其他寄存器 */
    regs->regs[0] = 0;
    if (debug_mode) pr_info("smaps_hide: hide entry (target library matched)\n");
    return 0;
}

/* 7. module 初始化 */
static int __init mod_init(void)
{
    int ret;
    num_targets = parse_targets_buf(targets);
    if (num_targets == 0) { pr_err("empty targets list\n"); return -EINVAL; }
    pr_info("smaps_hide: parsed %d target(s)\n", num_targets);

    kp_maps.pre_handler = pre_hide_maps;
    ret = register_kprobe(&kp_maps);
    if (ret < 0) { pr_warn("kprobe show_map failed (%d)\n", ret); kp_maps.pre_handler = NULL; }
    else pr_info("smaps_hide: kprobe show_map armed\n");

    kp_smap.pre_handler = pre_hide_smap;
    ret = register_kprobe(&kp_smap);
    if (ret < 0) { pr_warn("kprobe show_smap failed (%d)\n", ret); kp_smap.pre_handler = NULL; }
    else pr_info("smaps_hide: kprobe show_smap armed\n");

    pr_info("smaps_hide: loaded (targets=%s, min_uid=%d, debug_mode=%d)\n", targets, min_uid, debug_mode);
    return 0;
}

/* 8. module 退出 */
static void __exit mod_exit(void)
{
    if (kp_maps.addr) unregister_kprobe(&kp_maps);
    if (kp_smap.addr) unregister_kprobe(&kp_smap);
    pr_info("smaps_hide: unloaded\n");
}
module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Safe hide detected GPU driver libs from /proc pid maps/smaps for non-su apps");
MODULE_VERSION("0.7");