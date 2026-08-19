#!/system/bin/sh
# optional overrides (edit before install):
# TARGETS="adreno,libllvm,qspmhal"
# MIN_UID=10000
MODDIR=${0%/*}
KO="$MODDIR/smaps_hide.ko"
LOG=/data/local/tmp/smaps_hide.log
[ -f "$KO" ] || exit 0
ARGS=""
[ -n "$TARGETS" ] && ARGS="$ARGS targets=\"$TARGETS\""
[ -n "$MIN_UID" ] && ARGS="$ARGS min_uid=$MIN_UID"
if insmod "$KO" $ARGS 2>/dev/null; then
  echo "[smaps_hide] loaded $(date +%s)" >> "$LOG"
elif insmod -f "$KO" $ARGS 2>/dev/null; then
  echo "[smaps_hide] loaded (forced) $(date +%s)" >> "$LOG"
else
  echo "[smaps_hide] FAILED to load $(date +%s) : $(lsmod | grep -c smaps_hide)" >> "$LOG"
fi
