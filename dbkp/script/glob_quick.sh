#!/bin/bash
# glob 测试：验证 ** 递归通配符
B=/c/Users/user/Desktop/develop/software-develop/dbkp
BK="$B/bin/bk.exe"
EXE="$B/execit.exe"
G="$B/_globtest"

cd "$B" || exit 9
rm -rf "$G"
mkdir -p "$G/src/sub/deep"
printf hello > "$G/src/a.txt"
printf world > "$G/src/sub/b.txt"
printf deep > "$G/src/sub/deep/c.txt"

run() { "$EXE" "$(cygpath -w "$BK")" "$@"; echo "EXIT=$?"; }

W="$(cygpath -w "$G")"

echo "=== T1: --include '**/*' ==="
run backup "$W\src" "$W\out1" --include '**/*'
ls -R "$G/out1" 2>/dev/null | head -20

echo "=== T2: --include '*.txt' ==="
run backup "$W\src" "$W\out2" --include '*.txt'
ls -R "$G/out2" 2>/dev/null | head -20

echo "=== T3: --include 'sub/*.txt' ==="
run backup "$W\src" "$W\out3" --include 'sub/*.txt'
ls -R "$G/out3" 2>/dev/null | head -20

echo "=== T4: --include 'src/**/*.h' (UI placeholder 风格, 无匹配) ==="
run backup "$W\src" "$W\out4" --include 'src/**/*.h'
ls -R "$G/out4" 2>/dev/null | head -20

echo "=== T5: 无 include 全量 ==="
run backup "$W\src" "$W\out5"
ls -R "$G/out5" 2>/dev/null | head -20

echo "=== T6: --include '**' ==="
run backup "$W\src" "$W\out6" --include '**'
ls -R "$G/out6" 2>/dev/null | head -20
