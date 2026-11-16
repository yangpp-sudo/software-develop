#!/bin/bash
# ** 递归通配符端到端验证 v2
B=/c/Users/user/Desktop/develop/software-develop/dbkp
RUN="$B/runwin.exe"
BKW='C:\Users\user\Desktop\develop\software-develop\dbkp\bin\bk.exe'
W='C:/Users/user/Desktop/develop/software-develop/dbkp/_globtest'

cd "$B" || exit 9
rm -rf /c/Users/user/Desktop/develop/software-develop/dbkp/_globtest
mkdir -p "$W/src/sub/deep" "$W/src/inc"
printf hello    > "$W/src/a.txt"
printf header1  > "$W/src/h1.h"
printf world    > "$W/src/sub/b.txt"
printf header2  > "$W/src/sub/h2.h"
printf deep     > "$W/src/sub/deep/c.txt"
printf header3  > "$W/src/inc/h3.h"

t() { echo "--- $1"; shift; "$RUN" "$BKW" "$@"; echo "[exit=$?]"; }

echo "######## T1 归档 --include **/* ########"
t backup backup "$W/src" "$W/a1.dbkp" --include "**/*"
"$RUN" "$BKW" list "$W/a1.dbkp" | tail -3
t restore restore "$W/a1.dbkp" "$W/rest1"
diff -r "$W/src" "$W/rest1" >/dev/null 2>&1 && echo "T1 RESTORE-DIFF: CLEAN" || echo "T1 RESTORE-DIFF: MISMATCH"

echo "######## T3 src/**/*.h：源目录=src 本身（应空箱失败 + 修复后的提示）########"
t backup backup "$W/src" "$W/a2.dbkp" --include "src/**/*.h"

echo "######## T3b src/**/*.h：源目录=父目录（正确的 placeholder 用法）########"
t backup backup "$W" "$W/a2b.dbkp" --include "src/**/*.h"
"$RUN" "$BKW" list "$W/a2b.dbkp" | grep -v "^D\|^T\|^total" | head
t restore restore "$W/a2b.dbkp" "$W/rest2"
find "$W/rest2" -type f 2>/dev/null | sed "s|$W/rest2/||" | sort

echo "######## T5 --exclude **/deep/** ########"
t backup backup "$W/src" "$W/a3.dbkp" --exclude "**/deep/**"
t restore restore "$W/a3.dbkp" "$W/rest3"
find "$W/rest3" -type f 2>/dev/null | sed "s|$W/rest3/||" | sort

echo "######## T7 copy 模式 --include **/* ########"
t backup-copy backup "$W/src" "$W/copy1" --include "**/*"
diff -r "$W/src" "$W/copy1" >/dev/null 2>&1 && echo "T7 COPY-DIFF: CLEAN" || echo "T7 COPY-DIFF: MISMATCH"

echo "######## T6 无过滤基线（对照）########"
t backup backup "$W/src" "$W/a4.dbkp" 2>&1 | grep -E "entries|exit"
