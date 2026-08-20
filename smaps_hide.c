/*
 * smaps_hide.c - 隐藏 /proc/<pid>/{maps,smaps} 中特定“检测点”库的路径。
 *
 * 安全设计（避免 Kernel panic，核心原则：绝不操纵控制流 / 栈帧 / 易变内部结构）：
 *  - 仅使用 kretprobe 挂载到 d_path：d_path 是把 vma->vm_file 渲染成路径字符串的函数，
 *    /proc/pid/{maps,smaps} 经由 seq_path -> d_path 打印文件路径。
 *  - kretprobe 在 d_path 返回【之后】触发，我们只就地改写【调用方提供的、可写的】路径
 *    缓冲区内的字符串，然后让原调用方照常打印改写后的内容。
 *  - 全程不修改任何内核结构体、不改动 regs->pc/regs->sp、不跳过任何函数指令、
 *    不解引用 vm_area_struct 等易变结构 => 不存在野指针解引用或栈帧破坏 => 不会 panic。
 *  - 任何判断失败都直接放行（return 0），绝不拦截。
 *
 * 作用范围：
 *  - 仅对 targets 中列出的 15 个 Adreno/LLVM GPU 驱动检测点库名（子串匹配）生效；
 *  - 仅对 uid >= min_uid 的读取者生效；
 *  - 当读取者是系统关键进程（protect 列表）时完全不干预，避免影响系统稳定性。
 *
 * Build & load for Android GKI android15-6.6 (ARM64, 4K pages).
 *   insmod -f smaps_hide.ko
 * 运行时关停（不必 rmmod）: echo 0 > /sys/module/smaps_hide/parameters/enabled
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rewrite 15 Adreno/LLVM GPU driver lib paths in /proc pid maps/smaps (kretprobe, panic-safe)");
MODULE_VERSION("0.4");

/* 默认仅针对这 15 个 Adreno/LLVM GPU 驱动检测点库名做隐藏（Duck Detector 报告项）。
 * 可 insmod 时通过 targets= 覆盖。 */
static char *targets =
	"libllvm-qgl.so,libadreno_app_profiles.so,libGLESv2_adreno.so,"
	"libllvm-glnext.so,libgsl.so,eglSubDriverAndroid.so,libEGL_adreno.so,"
	"vulkan.adreno.so,libmapperutils.so,libadreno_utils.so,libdmabufheap.so,"
	"vendor.qti.qspmhal-V1-ndk.so,libqspm-mem-utils-vendor.so,"
	"libGLESv1_CM_adreno.so,vendor.qti.hardware.hexlp-V2-ndk.so";
module_param(targets, charp, 0644);
MODULE_PARM_DESC(targets, "comma-separated path substrings to hide");

static int min_uid = 10000;
module_param(min_uid, int, 0644);
MODULE_PARM_DESC(min_uid, "only rewrite paths for readers whose uid >= min_uid");

/* 系统关键进程：作为读取方时绝不改写任何输出，避免影响系统稳定性。 */
static char *protect = "system_server,surfaceflinger,zygote,zygote64,init,logd,netd,ueventd,adbd,servicemanager,hwservicemanager,vold,zygote32";
module_param(protect, charp, 0644);
MODULE_PARM_DESC(protect, "comma-separated comms of system processes to never touch");

static int enabled = 1;
module_param(enabled, int, 0644);
MODULE_PARM_DESC(enabled, "master switch (1=on, 0=off)");

static bool comm_protected(const char *comm)
{
	char t[64]; const char *cur, *end; size_t len;
	if (!comm) return false;
	for (cur = protect; *cur; ) {
		while (*cur == ',') cur++;
		end = strchr(cur, ',');
		len = end ? (size_t)(end - cur) : strlen(cur);
		if (len == 0) { if (!end) break; cur = end + 1; continue; }
		if (len > 63) len = 63;
		memcpy(t, cur, len); t[len] = '\0';
		if (strncmp(comm, t, len) == 0) return true;
		if (!end) break;
		cur = end + 1;
	}
	return false;
}

static bool path_match(const char *p)
{
	char t[64]; const char *cur, *end; size_t len;
	if (!p || !*p) return false;
	for (cur = targets; *cur; ) {
		while (*cur == ' ' || *cur == ',') cur++;
		end = strchr(cur, ',');
		len = end ? (size_t)(end - cur) : strlen(cur);
		if (len == 0) { if (!end) break; cur = end + 1; continue; }
		if (len > 63) len = 63;
		memcpy(t, cur, len); t[len] = '\0';
		if (strstr(p, t)) return true;
		if (!end) break;
		cur = end + 1;
	}
	return false;
}

static int d_path_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	char *p;
	const char *comm = current->comm;
	uid_t uid;
	size_t len;

	if (!enabled) return 0;
	if (comm_protected(comm)) return 0;
	uid = from_kuid(&init_user_ns, current_uid());
	if (uid < (uid_t)min_uid) return 0;

	p = (char *)regs->regs[0];
	if (IS_ERR_OR_NULL(p)) return 0;
	if (!path_match(p)) return 0;

	len = strlen(p);
	if (len == 0) return 0;
	/* 就地改写：不改变长度、就地覆盖、补 \0；不触碰 regs / 任何内核结构。 */
	memcpy(p, "/dev/null", 9);
	if (len > 9) p[9] = '\0';
	return 0;
}

static struct kretprobe rp_d_path = {
	.handler = d_path_ret_handler,
	.maxactive = 64,
	.kp.symbol_name = "d_path",
};

static int __init smaps_hide_init(void)
{
	int r;
	r = register_kretprobe(&rp_d_path);
	if (r < 0) {
		pr_err("smaps_hide: register_kretprobe(d_path) failed: %d\n", r);
		return r;
	}
	pr_info("smaps_hide: loaded; hiding %s for uid>=%d (panic-safe d_path kretprobe)\n",
		targets, min_uid);
	return 0;
}

static void __exit smaps_hide_exit(void)
{
	unregister_kretprobe(&rp_d_path);
	pr_info("smaps_hide: unloaded\n");
}

module_init(smaps_hide_init);
module_exit(smaps_hide_exit);
