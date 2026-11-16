#!/usr/bin/env bash
# 攻击轮 4：文件系统形态 / 归档完整性 / restore 覆盖 / 并发竞争 / CLI 新形态
# 判定：runwin exit>=3 或 timeout=124 => 崩溃或挂起
#      BAIT*.txt 被改写 / 沙箱外出现新文件 => 逃逸（严重洞）
set +e
ROOT=/c/Users/user/Desktop/develop/software-develop/dbkp
BK="C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\bin\\bk.exe"
RUN=$ROOT/runwin.exe
W=$ROOT/_attack2
CB=C:/Users/user/Desktop/develop/software-develop/dbkp/_attack2
WS=$CB/src

rm -rf "$W"; mkdir -p "$W/src/sub" "$W/out" "$W/arc"
printf 'hello world 123' > "$W/src/a.txt"
printf 'data2' > "$W/src/b.txt"
mkdir -p "$W/src/sub/deep"
printf 'deepfile' > "$W/src/sub/deep/c.txt"
printf 'BAIT-DO-NOT-TOUCH' > "$W/BAIT.txt"
printf 'BAIT2-DO-NOT-TOUCH' > "$ROOT/BAIT2.txt"

TOTAL=0; CRASH=0; ESCAPE=0
bait_ok() {
  grep -q 'BAIT-DO-NOT-TOUCH' "$W/BAIT.txt" && grep -q 'BAIT2-DO-NOT-TOUCH' "$ROOT/BAIT2.txt"
}
r2() { # label, cmd...  => runwin bk
  local label="$1"; shift
  TOTAL=$((TOTAL+1))
  local out rc rx tag
  out=$(timeout 25 "$RUN" "$BK" "$@" 2>&1); rc=$?
  rx=$(echo "$out" | sed -n 's/.*\[runwin exit=\([0-9]*\)\].*/\1/p' | tail -1)
  tag="ok"
  if [ "$rc" -eq 124 ] || [ "${rx:-0}" -ge 3 ] 2>/dev/null || [ "$rc" -ge 3 ]; then
    tag="!!! CRASH/HANG"; CRASH=$((CRASH+1))
  fi
  printf '[%s] %-42s rc=%s rx=%s | %s\n' "$tag" "$label" "$rc" "${rx:-?}" "$(echo "$out" | tr '\n' ' ' | cut -c1-110)"
  bait_ok || { echo "  !!! BAIT 被改写!!!"; ESCAPE=$((ESCAPE+1)); }
}

echo "================ A 组: 源目录文件系统形态攻击 ================"
# A1 符号链接自循环 (Windows: cmd mklink 需要 symlink 权限，用目录内自指 junction 的替代——软链到自身)
cp -r "$W/src" "$W/src_loop"
ln -sf "$W/src_loop" "$W/src_loop/selfref" 2>/dev/null
r2 "A1 源目录含指向自身的符号链接" backup "$WS" "$CB/arc/a1.dbkp"
# A2 0 字节文件
mkdir -p "$W/src0"; : > "$W/src0/empty.txt"
r2 "A2 0字节文件" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\src0" "$CB/arc/a2.dbkp"
# A3 稀疏/较大文件 64MB
mkdir -p "$W/srcbig"
head -c 67108864 /dev/zero | tr '\0' 'Z' > "$W/srcbig/big.bin" 2>/dev/null || dd if=/dev/zero of="$W/srcbig/big.bin" bs=1M count=64 2>/dev/null
r2 "A3 64MB大文件备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\srcbig" "$CB/arc/a3.dbkp"
r2 "A3b 64MB大文件还原" restore "$CB/arc/a3.dbkp" "$CB/out/a3"
# A4 大量文件 (3000)
mkdir -p "$W/srcmany"; for i in $(seq 1 3000); do printf "x$i" > "$W/srcmany/f$i.txt"; done
r2 "A4 3000个文件目录备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\srcmany" "$CB/arc/a4.dbkp"
# A5 空目录
mkdir -p "$W/srcempty"
r2 "A5 完全空目录备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\srcempty" "$CB/arc/a5.dbkp"
# A6 只读文件
mkdir -p "$W/srcro"; printf ro > "$W/srcro/ro.txt"; chmod 444 "$W/srcro/ro.txt"
r2 "A6 含只读文件备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\srcro" "$CB/arc/a6.dbkp"
# A7 换行/特殊字符文件名
mkdir -p "$W/srcname"
printf x > "$W/srcname/only.ext"
printf y > "$W/srcname/.hidden"
printf z > "$W/srcname/..dots.."
printf w > "$W/srcname/空格 和 中文.txt"
r2 "A7 特殊字符文件名集合" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\srcname" "$CB/arc/a7.dbkp"

echo "================ B 组: 归档文件完整性攻击 ================"
# 正常归档做参照
"$RUN" "$BK" backup "$WS" "$CB/arc/good.dbkp" > /dev/null 2>&1
GOOD="$CB/arc/good.dbkp"; GMSYS=$W/arc/good.dbkp
# B1 归档截断 (保留前 60%)
sz=$(wc -c < "$GMSYS"); keep=$((sz*6/10))
head -c $keep "$GMSYS" > "$W/arc/trunc.dbkp"
r2 "B1 归档截断60%后restore" restore "$CB/arc/trunc.dbkp" "$CB/out/b1"
# B2 归档截断后 verify
r2 "B2 归档截断60%后verify" verify "$CB/arc/trunc.dbkp"
# B3 归档=空文件
: > "$W/arc/zero.dbkp"
r2 "B3 空文件当归档" restore "$CB/arc/zero.dbkp" "$CB/out/b3"
# B4 归档=目录
mkdir -p "$W/arc/dirdir"
r2 "B4 目录当归档" restore "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack2\\arc\\dirdir" "$CB/out/b4"
# B5 归档尾部追加垃圾
cp "$GMSYS" "$W/arc/appjunk.dbkp"; printf 'JUNKJUNKJUNK' >> "$W/arc/appjunk.dbkp"
r2 "B5 归档尾部追加垃圾" restore "$CB/arc/appjunk.dbkp" "$CB/out/b5"
# B6 归档中间翻转 64KB
cp "$GMSYS" "$W/arc/mid.dbkp"
python - <<'EOF'
f=open(r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack2/arc/mid.dbkp','r+b')
import os; s=os.fstat(f.fileno()).st_size
if s>70000:
    f.seek(s//2); f.write(b'\xFF'*(1<<16))
f.close()
EOF
r2 "B6 归档中部64KB翻转" restore "$CB/arc/mid.dbkp" "$CB/out/b6"
# B7 两份不同归档互换 (口令不匹配场景)
"$RUN" "$BK" backup "$WS" "$CB/arc/enc.dbkp" -a huffman -c aes256 -p "passONE" >/dev/null 2>&1
r2 "B7 错误口令还原加密归档" restore "$CB/arc/enc.dbkp" "$CB/out/b7" -p "passTWO"
r2 "B8 正确口令还原(对照)" restore "$CB/arc/enc.dbkp" "$CB/out/b8" -a huffman -c aes256 -p "passONE"

echo "================ C 组: restore 覆盖/越权写攻击 ================"
# C1 目标非空目录(含已有文件)
mkdir -p "$W/nonempty"; printf 'OLD-DATA' > "$W/nonempty/exists.txt"
r2 "C1 restore覆盖非空目录" restore "$CB/arc/good.dbkp" "$CB/nonempty"
grep -q 'hello world 123' "$W/nonempty/a.txt" 2>/dev/null && echo "  (覆盖生效: a.txt 已还原)" || echo "  (旧文件保留或部分还原)"
# C2 目标处有只读同名文件
mkdir -p "$W/rodst"; printf 'READONLY-OLD' > "$W/rodst/a.txt"; chmod 444 "$W/rodst/a.txt"
r2 "C2 restore覆盖只读同名文件" restore "$CB/arc/good.dbkp" "$CB/rodst"
chmod 644 "$W/rodst/a.txt" 2>/dev/null
# C3 目标=源目录自身(自递归写)
r2 "C3 restore目标=源目录" restore "$CB/arc/good.dbkp" "$CB/src"
# C4 目标=归档所在目录(还原出与归档同名风险)
r2 "C4 restore目标=归档所在目录" restore "$CB/arc/good.dbkp" "$CB/arc"

echo "================ D 组: 并发竞争攻击 ================"
# D1 4 个并发备份写同一个输出文件
for i in 1 2 3 4; do
  ( timeout 30 "$RUN" "$BK" backup "$WS" "$CB/arc/race$i.dbkp" -a huffman >/dev/null 2>&1 ) &
done
wait
r2 "D1 并发4备份后各自verify" verify "$CB/arc/race1.dbkp"
TOTAL=$((TOTAL+1)); ok=1
for i in 1 2 3 4; do
  out=$(timeout 20 "$RUN" "$BK" verify "$CB/arc/race$i.dbkp" 2>&1)
  echo "$out" | sed -n 's/.*\[runwin exit=\([0-9]*\)\].*/\1/p' | tail -1 | grep -qv '^0$' && { echo "  !!! race$i verify 非法"; ok=0; }
done
[ "$ok" = 1 ] && echo "[ok] D1b 4个并发归档全部 verify 通过"
bait_ok || { echo "  !!! BAIT 被改写!!!"; ESCAPE=$((ESCAPE+1)); }
# D2 2 个并发 restore 到同一目标
( timeout 30 "$RUN" "$BK" restore "$CB/arc/good.dbkp" "$CB/out/d2" >/dev/null 2>&1 ) &
( timeout 30 "$RUN" "$BK" restore "$CB/arc/good.dbkp" "$CB/out/d2" >/dev/null 2>&1 ) &
wait
TOTAL=$((TOTAL+1)); echo "[ok?] D2 双并发restore完成 (人工核查目标)"; ls "$W/out/d2" 2>/dev/null | head -5
bait_ok || { echo "  !!! BAIT 被改写!!!"; ESCAPE=$((ESCAPE+1)); }

echo "================ E 组: CLI 新形态参数 ================"
r2 "E1 空口令加密" backup "$WS" "$CB/arc/e1.dbkp" -c aes256 -p ""
r2 "E2 含换行口令" backup "$WS" "$CB/arc/e2.dbkp" -c aes256 -p "$(printf 'aa\nbb')"
r2 "E3 10000字符口令" backup "$WS" "$CB/arc/e3.dbkp" -c aes256 -p "$(head -c 10000 /dev/zero | tr '\0' 'P')"
r2 "E4 response file @" backup "$WS" "$CB/arc/e4.dbkp" @"$CB/arc/good.dbkp"
r2 "E5 newer-than未来时间" backup "$WS" "$CB/arc/e5.dbkp" --newer-than 2099-12-31T23:59:59
r2 "E6 min-size>max边界" backup "$WS" "$CB/arc/e6.dbkp" --min-size 999999999999999999999
r2 "E7 exclude=include同路径" backup "$WS" "$CB/arc/e7.dbkp" --include "$CB/src" --exclude "$CB/src"
r2 "E8 depth=0" backup "$WS" "$CB/arc/e8.dbkp" --max-depth 0
r2 "E9 备份到归档自身路径" backup "$WS" "$CB/arc/good.dbkp"
r2 "E10 verify不存在的归档" verify "$CB/arc/nope.dbkp"

echo "================ F 组: 收尾逃逸检查 ================"
TOTAL=$((TOTAL+1))
if bait_ok; then echo "[ok] F1 诱饵文件完好"; else echo "[!!!] F1 诱饵被改写 => 逃逸"; ESCAPE=$((ESCAPE+1)); fi
TOTAL=$((TOTAL+1))
extra=$(ls "$W" | grep -v -E '^(src|out|arc|src_loop|src0|srcbig|srcmany|srcempty|srcro|srcname|nonempty|rodst|BAIT.txt)$' | wc -l)
echo "[info] F2 沙箱内额外条目=$extra（归档/输出目录属正常）"
echo "================ TOTAL=$TOTAL CRASH/HANG=$CRASH ESCAPED=$ESCAPE ================"
