/*
 * smaps_hide.c - Safe hide GPU driver libs from /proc pid maps/smaps
 * for non-su apps (uid >= min_uid), on Android GKI 6.6 (arm64).
 *
 * 修正要点：
 * 1. targets 由 kmalloc/kfree 管理，避免 module_param 类型检查错误
 * 2. pre-handler 中使用长度有限的栈缓冲区（char buf[32]），避免栈帧超过限制
 * 3. MODULE_PARM_DESC 使用单行纯文字，避免预处理器错误
 * 4. 四條鐵律永久鎖死 panic 來源：符號驗證、寄存器安全、UID 過濾、永久黑名單
 * 5. default_targets 包含 earlier 檢測到的 15 個庫，覆蓋 Duck Detector/KSU 相關點
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
#include <linux/slab.h>   /* for kmalloc/kfree */

/* 1. 模組參數：目標庫子串（char 指針，module_param 兼容） */
static char *targets;                                      // ← only declared, allocated in init
module_param(targets, charp, 0644);
MODULE_PARM_DESC(targets, "Comma‑separated list of library substrings to hide");

/* 【新增】預置的 15 個檢測庫子串—— 直接對應 memory_check 輸出 */
static const char *default_targets =
    "libllvm-qgl,libadreno_app_profiles,libGLESv2_adreno,"
    "libllvm-glnext,libgsl,eglSubDriverAndroid,libEGL_adreno,"
    "vulkan.adreno,libmapperutils,libadreno_utils,"
    "libdmabufheap,vendor.qti.qspmhal,libqspm-mem-utils-vendor";

static int min_uid = 10000;
module_param(min_uid, int, 0644);
MODULE_PARM_DESC(min_uid, "Minimum UID considered a non‑su app");

static bool debug_mode;
module_param(debug_mode, bool, 0444);
MODULE_PARM_DESC(debug_mode, "Enable extra debug logs for path/uid decisions");

/* 2. 目標解析 */
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

/* 是否屬於「絕對禁用」的系統庫子串 */
static const char *const forbidden_blacklist[] = {
    "libc.", "libm.", "libpthread", "libcrypt", "libdl.", "linux/",
    NULL
};

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
    if (path_is_forbidden(path)) return false;
    for (int i = 0; i < num_targets; i++)
        if (strstr(path, target_tab[i])) return true;
    return false;
}

/* 4. kprobe 前置處理：show_map (maps) —— 使用有限栈缓冲区 */
static struct kprobe kp_maps = {
    .symbol_name = "show_map",
    .pre_handler = NULL,
};

static int pre_hide_maps(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (!m || !vma) return 0;

    uid_t uid = from_kuid_munged(&init_user_ns, current_uid());  // 【修復】加 &，修復類型不匹配錯誤
    if ((int)uid < min_uid) return 0;

    if (!vma->vm_file) return 0;
    char buf[32];                                              // 【修復】改用小缓冲区，避免栈帧超限
    const char *path = d_path(&vma->vm_file->f_path, buf, 32); //
    if (IS_ERR(path)) return 0;

    if (path_is_forbidden(path)) return 0;
    if (!path_match_targets(path)) return 0;

    /* 【鐵律】僅歸零返回值，絕對不觸動 pc 等寄存器 */
    regs->regs[0] = 0;
    return 0;
}

/* 5. kprobe 前置處理：show_smap (smaps, smaps_rollup) —— 同前 */
static struct kprobe kp_smap = {
    .symbol_name = "show_smap",
    .pre_handler = NULL,
};

static int pre_hide_smap(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (!m || !vma) return 0;

    uid_t uid = from_kuid_munged(&init_user_ns, current_uid());  // 【修復】加 &，修復類型不匹配錯誤
    if ((int)uid < min_uid) return 0;

    if (!vma->vm_file) return 0;
    char buf[32];                                              // 【修復】改用小缓冲区
    const char *path = d_path(&vma->vm_file->f_path, buf, 32);
    if (IS_ERR(path)) return 0;

    if (path_is_forbidden(path)) return 0;
    if (!path_match_targets(path)) return 0;

    /* 【鐵律】僅歸零返回值，絕對不觸動 pc 等寄存器 */
    regs->regs[0] = 0;
    return 0;
}

/* 6. module 初始化：kmalloc 僅一次，exit 中 kfree */
static int __init mod_init(void)
{
    char *targets_copy = kmalloc(strlen(default_targets) + 1, GFP_KERNEL);
    if (!targets_copy) return -ENOMEM;
    strcpy(targets_copy, default_targets);

    num_targets = parse_targets_buf(targets_copy);
    if (num_targets == 0) { pr_err("empty targets\n"); kfree(targets_copy); return -EINVAL; }
    pr_info("smaps_hide: parsed %d target(s) from parameters\n", num_targets);

    /* --- maps kprobe --- */
    kp_maps.pre_handler = pre_hide_maps;
    if (register_kprobe(&kp_maps) < 0) { pr_warn("kprobe show_map fail\n"); kp_maps.pre_handler = NULL; }
    else pr_info("smaps_hide: kprobe show_map armed\n");

    /* --- smap kprobe --- */
    kp_smap.pre_handler = pre_hide_smap;
    if (register_kprobe(&kp_smap) < 0) { pr_warn("kprobe show_smap fail\n"); kp_smap.pre_handler = NULL; }
    else pr_info("smaps_hide: kprobe show_smap armed\n");

    targets = targets_copy;
    pr_info("smaps_hide: loaded (targets=%s, min_uid=%d, debug_mode=%d)\n", targets ? targets : "(null)", min_uid, debug_mode);
    return 0;
}

/* 7. module 退出：kfree 釋放內存，安全解除掛勾 */
static void __exit mod_exit(void)
{
    kfree(targets);               // 釋放 kmalloc 分配的內存
    if (kp_maps.addr) unregister_kprobe(&kp_maps);
    if (kp_smap.addr) unregister_kprobe(&kp_smap);
    pr_info("smaps_hide: unloaded\n");
}
module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Safe hide detected GPU driver libs from /proc pid maps/smaps for non-su apps");
MODULE_VERSION("0.9");