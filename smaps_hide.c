/*
 * smaps_hide.c - Hide GPU driver libraries from /proc/<pid>/{maps,smaps,smaps_rollup}
 * for non-su apps (uid >= min_uid), via kprobes on:
 *   - show_map         (/proc/pid/maps, per-VMA .show; hide the whole entry)
 *   - show_smap        (/proc/pid/smaps & smaps_rollup, per-VMA .show; hide the whole entry)
 *
 * Build for Android GKI android15-6.6 (ARM64, 4K pages).
 * Load: insmod -f smaps_hide.ko targets="adreno,llvm,qspmhal" min_uid=10000
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
#include <linux/cred.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide adreno GPU driver libs from /proc pid maps/smaps for non-su apps");
MODULE_VERSION("0.1");

static char *targets = "adreno,libllvm,qspmhal,libCB.so,libOpenCL,libgsl,libkcl,libgame,libgpu,libadreno,libdmabuf,libmapper,libqspm,hexlp,vulkan.adreno";
module_param(targets, charp, 0644);

static int min_uid = 10000;
module_param(min_uid, int, 0644);

struct proc_maps_priv_min {
    struct inode *inode;
    struct task_struct *task;
};

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
}

static struct task_struct *seq_task(struct seq_file *m)
{
    struct proc_maps_priv_min *pm = m ? (struct proc_maps_priv_min *)m->private : NULL;
    return pm ? pm->task : NULL;
}

static bool should_hide(struct task_struct *task, struct vm_area_struct *vma)
{
    char *buf, *p;
    bool match = false;
    if (!task || !vma || !vma->vm_file) return false;
    rcu_read_lock();
    if (from_kuid(&init_user_ns, task_cred_xxx(task, uid)) < (uid_t)min_uid) {
        rcu_read_unlock();
        return false;
    }
    rcu_read_unlock();
    buf = (char *)__get_free_page(GFP_KERNEL);
    if (!buf) return false;
    p = d_path(&vma->vm_file->f_path, buf, PAGE_SIZE);
    if (!IS_ERR(p)) match = path_match(p);
    free_page((unsigned long)buf);
    return match;
}

static int pre_show_map(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (m && vma && should_hide(seq_task(m), vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
}

static int pre_show_smap(struct kprobe *kp, struct pt_regs *regs)
{
    struct seq_file *m = (struct seq_file *)regs->regs[0];
    struct vm_area_struct *vma = (struct vm_area_struct *)regs->regs[1];
    if (m && vma && should_hide(seq_task(m), vma)) {
        regs->regs[0] = 0;
        regs->pc = regs->regs[30];
    }
    return 0;
}

static struct kprobe kp_show_map  = { .symbol_name = "show_map",  .pre_handler = pre_show_map };
static struct kprobe kp_show_smap = { .symbol_name = "show_smap", .pre_handler = pre_show_smap };

static int reg_kp(struct kprobe *kp, const char *name)
{
    int r = register_kprobe(kp);
    if (r < 0) pr_warn("smaps_hide: kprobe %s failed (%d)\n", name, r);
    else       pr_info("smaps_hide: kprobe %s armed\n", name);
    return r;
}

static int __init smaps_hide_init(void)
{
    reg_kp(&kp_show_map,  "show_map");
    reg_kp(&kp_show_smap, "show_smap");
    pr_info("smaps_hide: loaded, targets=%s min_uid=%d\n", targets, min_uid);
    return 0;
}

static void __exit smaps_hide_exit(void)
{
    if (kp_show_map.addr)  unregister_kprobe(&kp_show_map);
    if (kp_show_smap.addr) unregister_kprobe(&kp_show_smap);
    pr_info("smaps_hide: unloaded\n");
}

module_init(smaps_hide_init);
module_exit(smaps_hide_exit);
