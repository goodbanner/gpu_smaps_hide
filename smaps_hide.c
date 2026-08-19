/*
 * smaps_hide.c - Hide GPU driver libraries from /proc/<pid>/{maps,smaps,smaps_rollup}
 * for app readers (current_euid() >= min_uid, default 10000), via kprobes on:
 *   - show_map          (/proc/pid/maps per-VMA .show -> hide the whole entry)
 *   - smaps_pte_range   (/proc/pid/smaps per-PMD stats walker -> zero out Swap/Shared_Dirty)
 *   - show_smap         (smaps_rollup)
 *
 * Gate is on the READER's uid, so system tools (debuggerd, profilers, tombstone)
 * still see everything; only uid>=10000 apps get the filtered view.
 *
 * Build for Android GKI android15-6.6 (ARM64, 4K pages). Load: insmod(-f) smaps_hide.ko
 * targets="adreno,libllvm,qspmhal" min_uid=10000
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide adreno GPU driver libs from /proc pid maps/smaps for uid>=min_uid readers");
MODULE_VERSION("0.2");

/* comma separated substrings matched against the mapped file's /proc path */
static char *targets = "adreno,libllvm,qspmhal,libCB.so,libOpenCL,libgsl,libkcl,libgame,libgpu,libadreno,libdmabuf,libmapper,libqspm,hexlp,vulkan.adreno";
module_param(targets, charp, 0644);

static int min_uid = 10000;
module_param(min_uid, int, 0644);

static bool path_match(const char *path)
{
    char *cur = targets;
    static char t[64];
    if (!path)
        return false;
    while (cur && *cur) {
        char *comma = strchr(cur, ',');
        size_t len = comma ? (size_t)(comma - cur) : strlen(cur);
        if (!len)
            break;
        if (len >= sizeof(t))
            len = sizeof(t) - 1;
        memcpy(t, cur, len);
        t[len] = '\0';
        if (strstr(path, t))
            return true;
        if (!comma)
            break;
        cur = comma + 1;
    }
    return false;
}

/* Reader-side gating + file-path matching (no dependency on proc private structs) */
static bool should_hide(struct vm_area_struct *vma)
{
    char *buf, *p;
    bool match = false;
    if (!vma || !vma->vm_file)
        return false;
    if (from_kuid(&init_user_ns, current_euid()) < (uid_t)min_uid)
        return false;
    buf = (char *)__get_free_page(GFP_KERNEL);
    if (!buf)
        return false;
    p = d_path(&vma->vm_file->f_path, buf, PAGE_SIZE);
    if (!IS_ERR(p))
        match = path_match(p);
    free_page((unsigned long)buf);
    return match;
}

/* show_map(struct seq_file *m, void *v) -> int ; skip = pretend it returned 0 */
static int pre_show_map(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (should_hide(vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
}

/* smaps_pte_range(pmd_t*, unsigned long, unsigned long, struct mm_walk*) -> int */
static int pre_smaps_pte(struct kprobe *kp, struct pt_regs *regs)
{
    struct mm_walk *walk = (struct mm_walk *)regs->regs[3];
    if (walk && should_hide(walk->vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
}

/* show_smap(struct seq_file *m, void *v) -> int */
static int pre_show_smap(struct kprobe *kp, struct pt_regs *regs)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (should_hide(vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
}

static struct kprobe kp_show_map  = { .symbol_name = "show_map",      .pre_handler = pre_show_map };
static struct kprobe kp_smaps_pte = { .symbol_name = "smaps_pte_range", .pre_handler = pre_smaps_pte };
static struct kprobe kp_show_smap = { .symbol_name = "show_smap",     .pre_handler = pre_show_smap };

static int reg_kp(struct kprobe *kp, const char *name)
{
    int r = register_kprobe(kp);
    if (r < 0)
        pr_warn("smaps_hide: kprobe %s failed (%d)\n", name, r);
    else
        pr_info("smaps_hide: kprobe %s armed\n", name);
    return r;
}

static int __init smaps_hide_init(void)
{
    reg_kp(&kp_show_map, "show_map");
    reg_kp(&kp_smaps_pte, "smaps_pte_range");
    reg_kp(&kp_show_smap, "show_smap");
    pr_info("smaps_hide: loaded, targets=%s min_uid=%d\n", targets, min_uid);
    return 0;
}

static void __exit smaps_hide_exit(void)
{
    if (kp_show_map.addr)  unregister_kprobe(&kp_show_map);
    if (kp_smaps_pte.addr) unregister_kprobe(&kp_smaps_pte);
    if (kp_show_smap.addr) unregister_kprobe(&kp_show_smap);
    pr_info("smaps_hide: unloaded\n");
}

module_init(smaps_hide_init);
module_exit(smaps_hide_exit);
