# smaps_hide — hide GPU driver libs from /proc/pid/{maps,smaps,smaps_rollup}

Kprobe-based kernel module for Android GKI `android15-6.6` (ARM64, 4K pages).
It hides the Adreno/LLVM GPU driver shared libraries from the smaps/maps view
of non-su apps (uid >= `min_uid`, default 10000), targeting the "swapped
executable pages" / "shared-dirty system code" checks used by detectors such
as Duck Detector.

## What it hooks (kallsyms-verified on 6.6.147-android15-...-4k)
- `show_map`          -> hides the whole entry of a target lib in /proc/pid/maps
- `smaps_pte_range`   -> suppresses Swap:/Shared_Dirty: accumulation for target
  libs in /proc/pid/smaps  (smaps_show is inlined on this kernel, so we hook the
  per-PMD stats walker instead)
- `show_smap`         -> same for smaps_rollup

## Match / scope
- Path substring match against the mapped file (defaults:
  adreno,libllvm,qspmhal,libCB.so,libOpenCL,libgsl,libkcl,libgame,libgpu,
  libadreno,libdmabuf,libmapper,libqspm,hexlp,vulkan.adreno)
- Only effective for target processes with uid >= min_uid (10000), so system
  processes/debuggers still see everything.

## Build
### via GitHub Actions (easiest)
1. Push this repo to GitHub; trigger `build-smaps-hide` (workflow_dispatch).
   The workflow checks out AOSP common kernel `android15-6.6` (default SHA
   `004a97f76e10`, matching the tested device), runs `gki_defconfig` +
   `modules_prepare`, builds `smaps_hide.ko`, and uploads it as an artifact.
2. Download the artifact, place `smaps_hide.ko` next to `module/` contents,
   zip the module folder as `smaps_hide.zip`.

### locally
   export KDIR=/path/to/android15-6.6-kernel
   ./build_module.sh

## Install as KSU module
Zip the module dir (module.prop + post-fs-data.sh + smaps_hide.ko) and install
through KernelSU manager, or unzip into /data/adb/modules/smaps_hide and reboot.
The kernel on the tested device tolerates vermagic/modversion drift (existing
6.6.127/6.6.111-built .ko load fine), so `insmod -f` fallback is included.

## Params
- `targets="a,b,c"`  comma-separated path substrings (defaults above)
- `min_uid=10000`    only hide for processes with uid >= this

## Caveats
- Kernel module: test in a recoverable environment first (panic risk).
- The module itself appears in /proc/modules (not hidden).
- smaps entries show the path header with zeroed stats (Swap/Shared_Dirty gone).
