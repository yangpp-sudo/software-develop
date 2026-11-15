#!/bin/bash
# A1: schedule/watch 的 --prefix 穿越（CLI 端到端）。诱饵文件必须完好，箱子不得写到 out 外。
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_probe/challenge/a1"
WWIN='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/a1'
BKW='C:\Users\user\Desktop\develop\software-develop\dbkp\bin\bk.exe'
RUN="$B/runwin.exe"

cd "$B" || exit 9
rm -rf "$W"
mkdir -p "$W/src" "$W/out"
printf 'SECRET-SRC' > "$W/src/a.txt"
printf 'BAIT-TOP-MUST-SURVIVE' > "$W/BAIT-prefix-20260101-00000-000.dbkp"
mkdir -p "$B/_probe/challenge"
printf 'BAIT-PARENT-MUST-SURVIVE' > "$B/_probe/challenge/BAIT-prefix-20260101-00000-000.dbkp"

echo "=== A1-1 schedule --prefix 带 ..\\ ==="
"$RUN" "$BKW" schedule "$WWIN/src" "$WWIN/out" --every 1s --times 2 --keep 1 --prefix '..\..\BAIT-prefix' 2>&1
echo "[exit=$?]"

echo "=== A1-2 watch --prefix 带 ..\\（watch 会常驻，用 timeout 兜底 4s）==="
timeout 4 "$RUN" "$BKW" watch "$WWIN/src" "$WWIN/out" --debounce 1s --keep 1 --prefix '..\..\BAIT-prefix' 2>&1 | head -8
echo "[watch done]"

echo "=== 落点检查 ==="
echo "--- out/ 内文件 ---"; find "$W/out" -type f 2>/dev/null | sed "s|$W/||"
echo "--- a1 根下所有 .dbkp（应只有诱饵）---"; find "$W" -name '*.dbkp' -type f | sed "s|$B/||"
echo "--- 诱饵内容（应仍是原文）---"
printf '  BAIT-TOP    = '; cat "$W/BAIT-prefix-20260101-00000-000.dbkp"; echo
printf '  BAIT-PARENT = '; cat "$B/_probe/challenge/BAIT-prefix-20260101-00000-000.dbkp"; echo
