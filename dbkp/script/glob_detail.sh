#!/bin/bash
# 4 种 glob 模式的 list 明细（挑战方第 2 条）
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_globdetail"
WW='C:/Users/user/Desktop/develop/software-develop/dbkp/_globdetail'
BKW='C:\Users\user\Desktop\develop\software-develop\dbkp\bin\bk.exe'
RUN="$B/runwin.exe"
cd "$B" || exit 9
rm -rf "$W"; mkdir -p "$W/src/sub/deep" "$W/src/inc"
printf hello   > "$W/src/a.txt"
printf header1 > "$W/src/h1.h"
printf world   > "$W/src/sub/b.txt"
printf header2 > "$W/src/sub/h2.h"
printf deep    > "$W/src/sub/deep/c.txt"
printf header3 > "$W/src/inc/h3.h"

probe() {
  local tag="$1"; shift
  echo "######## $tag ########"
  "$RUN" "$BKW" backup "$WW/src" "$WW/$tag.dbkp" "$@" 2>&1 | grep -E "entries :|backup ok|ERROR|WARN"
  echo "--- list ---"
  "$RUN" "$BKW" list "$WW/$tag.dbkp" 2>&1 | grep -vE "^\[runwin|^$"
  echo
}
probe 'p1' --include '**/*'
probe 'p2' --include '**/*.txt'
probe 'p3' --include 'sub/**/*.txt'
probe 'p4' --include '**/deep/**'
echo "######## p5  --exclude '**/deep/**' ########"
"$RUN" "$BKW" backup "$WW/src" "$WW/p5.dbkp" --exclude '**/deep/**' 2>&1 | grep -E "entries :|backup ok|ERROR|WARN"
echo "--- list ---"
"$RUN" "$BKW" list "$WW/p5.dbkp" 2>&1 | grep -vE "^\[runwin|^$"
