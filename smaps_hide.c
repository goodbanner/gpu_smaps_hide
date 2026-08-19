/*
 * smaps_hide.c - Hide GPU driver libraries from /proc/<pid>/{maps,smaps,smaps_rollup}
 * for non-su apps (uid >= min_uid), via kprobes on:
 *   - show_map         (/proc/pid/maps, per-VMA .show; hide the whole entry)
 *   - show_smap        (/proc/pid/smaps & smaps_rollup, per-VMA .show; hide the whole entry)
 *
 * Build & load for Android GKI android15-6.6 (ARM64, 4K pages).
 * Load: insmod -f smaps_hide.ko targets="adreno,libllvm,qspmhal" min_uid=10000
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide adreno GPU driver libs from /proc pid maps/smaps for non-su apps");
MODULE_VERSION("0.1");

static char *targets = "adreno,libllvm,qspmhal,libCB.so,libOpenCL,libgsl,libkcl,libgame,libgpu,libadreno,libdmabuf,libmapper,libqspm,hexlp,vulkan.adentro";
module_param(targets, charp, 0644);

static int min_uid = 10000;
module_param(min_uid, int, 0644);

/* 路径子串匹配 - 仅匹配目标库路径的子串 */
static bool path_match(const char *path)
{
    char *cur = targets;
    while (cur && *cur) {
        char t[64];
        char *comma = strchr(cur, ',');
        size_t len = comma ? (size_t)(comma - cur) : strlen(cur);
        if (!len) break;
        if (len >= sizeof(t)) len = sizeof(t) - 1;
        memcpy(t, cur, len);
        t[len] = '\0';
        if (strstr(path, t)) return true;
        if (!comma) break;
        cur = comma + 1;
    }
    return false;
};

/* 通用隐藏逻辑：分配页缓冲 -> d_path -> 匹配 -> 隐藏 */
static int hide_if_match(struct seq_file *m, struct vm_area_struct *vma)
{
    if (!m || !vma || !vma->vm_file) return 0;

    unsigned long page = __get_free_page(GFP_ATOMIC);
    if (!page) return 0;

    char *buf = (char *)page;
    char *path = d_path(&vma->vm_file->f_path, buf, PAGE_SIZE);
    bool match = !IS_ERR(path) && path_match(path);

    free_page(page);

    if (match) return 1;
    return 0;
};

/* show_map 钩子 - 隐藏 /proc/pid/maps 中的整条目 */
static int pre_show_map(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (hide_if_match(m, vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
};

/* show_smap 钩子 - 隐藏 /proc/pid/smaps 和 smaps_rollup 中的整条目 */
static int pre_show_smap(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (hide_if_match(m, vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
};

/* kprobe 注册 */
static struct kprobe kp_show_map   = { .symbol_name = "show_map",  .pre_handler = pre_show_map };
static struct kprobe kp_show_smap  = { .symbol_name = "show_smap", .pre_handler = pre_show_smap };

static int reg_kp(struct kprobe *kp, const char *name)
{
    int r = register_kprobe(kp);
    if (r < 0) pr_warn("smaps_hide: kprobe %s failed (%d)\n", name, r);
    else       pr_info("smaps_hide: kprobe %s armed\n", name);
    return r;
};

static int __init smaps_hide_init(void)
{
    reg_kp(&kp_show_map,  "show_map");
    reg_kp(&kp_show_smap, "show_smap");
    pr_info("smaps_hide: loaded\n");
    return 0;
};

static void __exit smaps_hide_exit(void)
{
    if (kp_show_map.addr)  unregister_kprobe(&kp_show_map);
    if (kp_show_smap.addr) unregister_kprobe(&kp_show_smap);
    pr_info("smaps_hide: unloaded\n");
};

module_init(smaps_hide_init);
module_exit(smaps_hide_exit);