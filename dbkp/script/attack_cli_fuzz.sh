#!/usr/bin/env bash
# 攻击轮 1：CLI 参数层不讲道理 fuzz（不讲道理 / 破坏性 / 进攻性）
# 判定：runwin exit>=3 或 timeout=124 => 崩溃或挂起（严重洞）
#      非法值却 exit=0/124 => 静默接受（洞）
#      恶意路径导致箱外文件出现 => 逃逸（严重洞）
set +e
ROOT=/c/Users/user/Desktop/develop/software-develop/dbkp
BK="C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\bin\\bk.exe"
BKD="C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\bin\\bkd.exe"
RUN=$ROOT/runwin.exe
W=$ROOT/_attack
rm -rf "$W"; mkdir -p "$W/src/sub" "$W/out"
printf 'hello' > "$W/src/a.txt"
printf 'world' > "$W/src/b.txt"
printf 'deep'  > "$W/src/sub/c.txt"
printf 'BAIT-DO-NOT-TOUCH' > "$W/BAIT.txt"
printf 'BAIT2-DO-NOT-TOUCH' > "$ROOT/BAIT2.txt"
LONG=$(head -c 30000 /dev/zero | tr '\0' 'A')

TOTAL=0; CRASH=0; SILENT=0; ESCAPE=0

rexit() { echo "$1" | sed -n 's/.*\[runwin exit=\([0-9]*\)\].*/\1/p' | tail -1; }
brief() { echo "$1" | tr '\n' ' ' | sed 's/  */ /g' | cut -c1-150; }

# ---- bk.exe 通用命令 fuzz：期望"不崩溃、不静默接受非法值" ----
atk() {
  local label="$1"; expect="$2"; shift 2
  TOTAL=$((TOTAL+1))
  out=$(timeout 10 "$RUN" "$BK" "$@" 2>&1); rc=$?
  local rx; rx=$(rexit "$out")
  local tag="ok"
  if [ "$rc" -eq 124 ] || [ "${rc:-0}" -ge 3 ]; then tag="CRASH/HANG"; CRASH=$((CRASH+1))
  elif [ -n "$rx" ] && [ "$rx" -ge 3 ] 2>/dev/null; then tag="CRASH"; CRASH=$((CRASH+1))
  elif [ "$expect" = "reject" ] && { [ -z "$rx" ] || [ "$rx" = "0" ]; }; then tag="SILENT-ACCEPT"; SILENT=$((SILENT+1)); fi
  printf '[%s] %-38s rx=%s rc=%s | %s\n' "$tag" "$label" "${rx:-?}" "$rc" "$(brief "$out")"
}

# ---- bkd.exe 启动参数 fuzz：非法值必须立即 exit=2（不能挂起=静默接受） ----
atkd() {
  local label="$1"; shift
  TOTAL=$((TOTAL+1))
  out=$(timeout 6 "$RUN" "$BKD" "$@" 2>&1); rc=$?
  local rx; rx=$(rexit "$out")
  local tag="ok(rejected)"
  if [ "$rc" -eq 124 ]; then tag="SILENT-ACCEPT(server ran)"; SILENT=$((SILENT+1))
  elif [ -n "$rx" ] && [ "$rx" -ge 3 ] 2>/dev/null; then tag="CRASH"; CRASH=$((CRASH+1))
  elif echo "$out" | grep -qi "invalid\|expected\|out of range"; then tag="ok(rejected)"
  else tag="UNKNOWN"; fi
  printf '[%s] %-38s rx=%s rc=%s | %s\n' "$tag" "$label" "${rx:-?}" "$rc" "$(brief "$out")"
}

echo "================ A 组: bkd 数值参数越界/畸形（期望全部拒绝） ================"
for v in 0 -5 4097 abc 1e3 0x10 +5 " 5 " 5.5 5x 99999999999999999999 -0 2147483648 4294967296 "1;2" "5%00" ""; do
  atkd "max-pending=[$v]" --max-pending "$v" --port 0
done
for v in 0 -5 9 abc 99999999999999999999 2.5; do atkd "workers=[$v]" --workers "$v" --port 0; done
for v in 0 -1 1025 abc 99999999999999999999; do atkd "max-body=[$v]" --max-body "$v" --port 0; done
for v in -1 65536 abc 99999999999 "-0"; do atkd "port=[$v]" --port "$v"; done
for v in -1 8761 abc 99999999999999999999; do atkd "token-ttl=[$v]" --token-ttl "$v" --port 0; done

echo "================ B 组: 配置文件注入非法值 ================"
mkdir -p "$W/cfg"
printf '{"maxPending":-5}' > "$W/cfg/c1.json"; atkd "config maxPending=-5" --config "$W/cfg/c1.json" --port 0
printf '{"workers":0}'      > "$W/cfg/c2.json"; atkd "config workers=0"      --config "$W/cfg/c2.json" --port 0
printf '{"port":99999}'     > "$W/cfg/c3.json"; atkd "config port=99999"     --config "$W/cfg/c3.json" --port 0
printf '{"maxBodyMb":0}'    > "$W/cfg/c4.json"; atkd "config maxBodyMb=0"    --config "$W/cfg/c4.json" --port 0
printf 'not-json-at-all{{'  > "$W/cfg/c5.json"; atkd "config 非法JSON"       --config "$W/cfg/c5.json" --port 0
printf '{"maxPending":1e9}' > "$W/cfg/c6.json"; atkd "config 科学计数法"     --config "$W/cfg/c6.json" --port 0

echo "================ C 组: -c/-a/--checksum 未知算法与畸形名 ================"
for v in aes999 AES256 "none " "" "$LONG" "%s%s%n" xor-typo "中文算法" "aes256;rm" "none\0x"; do
  atk "crypto=[${v:0:20}]" reject backup "$W/src" "$W/out/c.dbkp" -c "$v" -p x --force
done
for v in huffmanX "" "$LONG" "%s%s%n" "huffman;rm" "LZ77"; do
  atk "algo=[${v:0:20}]" reject backup "$W/src" "$W/out/a.dbkp" -a "$v" --force
done
for v in crc99 sha256X "" "$LONG" "%s%s%n"; do
  atk "checksum=[${v:0:20}]" reject backup "$W/src" "$W/out/k.dbkp" --checksum "$v" --force
done

echo "================ D 组: 口令 / 注释 / 类型 畸形 ================"
for v in "" "$LONG" "%s%s%n" "p@ss;drop" "口令中文"; do
  atk "password=[${v:0:16}]" any backup "$W/src" "$W/out/p.dbkp" -c aes256 -p "$v" --force
done
for v in "$LONG" "%s%s%n" "comment;rm -rf"; do
  atk "comment=[${v:0:16}]" any backup "$W/src" "$W/out/m.dbkp" -m "$v" --force
done
for v in "-DLX" "" "$LONG" "%s%s%n" "regular,../../evil"; do
  atk "type=[${v:0:20}]" reject backup "$W/src" "$W/out/t.dbkp" --type "$v" --force
done

echo "================ E 组: 数值/尺寸/时间/glob 畸形 ================"
for v in -1 0 abc 99999999999999999999 1e3 0x10 "10 KB" "-5KB" "NaN" "inf"; do
  atk "min-size=[$v]" reject backup "$W/src" "$W/out/s.dbkp" --min-size "$v" --force
done
for v in -1 abc 99999999999999999999 0x10 "3.5"; do
  atk "max-depth=[$v]" reject backup "$W/src" "$W/out/d.dbkp" --max-depth "$v" --force
done
for v in "[" "**" "$LONG" "%s%s%n" "" "a/../\evil"; do
  atk "include=[${v:0:20}]" any backup "$W/src" "$W/out/i.dbkp" --include "$v" --force
done
for v in "[" "$LONG" "%s%s%n"; do
  atk "exclude=[${v:0:20}]" any backup "$W/src" "$W/out/e.dbkp" --exclude "$v" --force
done
for v in "not-a-date" "99999999999999999999d" "-7d" "%s%s%n"; do
  atk "newer-than=[$v]" reject backup "$W/src" "$W/out/n.dbkp" --newer-than "$v" --force
done

echo "================ F 组: 路径注入 / 逃逸 / 设备名 / 超长 ================"
atk "src=父目录.."            reject backup "$W/src/.." "$W/out/f1.dbkp" --force
atk "box=../逃逸"             reject backup "$W/src" "$W/out/../ESCAPED.dbkp" --force
atk "box=绝对路径带盘符"      reject backup "$W/src" "C:\\Windows\\Temp\\pwn.dbkp" --force
atk "box=CON设备名"           reject backup "$W/src" "$W/out/CON" --force
atk "box=NUL.txt"             reject backup "$W/src" "$W/out/NUL.txt" --force
atk "box=ADS冒号"             reject backup "$W/src" "$W/out/x.dbkp:pwn" --force
atk "box=超长200K"            reject backup "$W/src" "$W/out/$LONG" --force
atk "box=格式串"              reject backup "$W/src" "$W/out/%s%s%n.dbkp" --force
atk "box=分号注入"            reject backup "$W/src" "$W/out/x.dbkp;rm -rf x" --force
atk "restore dst=..\..\逃逸"  reject restore "$W/out/c.dbkp" "$W/../../ESCAPED_RESTORE" --force
atk "restore 无箱"            reject restore "$W/nonexistent.dbkp" "$W/out/r" --force
atk "verify 不存在"           reject verify "$W/nonexistent.dbkp"
atk "list 不存在"             reject list "$W/nonexistent.dbkp"

echo "================ G 组: 重复参数 / 参数顺序 / 诡异开关 ================"
atk "重复-a 最后生效"         any backup "$W/src" "$W/out/g1.dbkp" -a none -a huffmanX --force
atk "重复-c 最后生效"         any backup "$W/src" "$W/out/g2.dbkp" -c none -c aes999 --force
atk "--max-pending给bk"       reject backup "$W/src" "$W/out/g3.dbkp" --max-pending 0 --force
atk "未知开关"                reject backup "$W/src" "$W/out/g4.dbkp" --no-such-flag --force
atk "help混入"                any backup "$W/src" "$W/out/g5.dbkp" -h --force
atk "selftest"                any selftest

echo "================ H 组: 破坏性后果检查 ================"
# 诱饵文件是否被改写
if grep -q BAIT-DO-NOT-TOUCH "$W/BAIT.txt" && grep -q BAIT2-DO-NOT-TOUCH "$ROOT/BAIT2.txt"; then
  echo "[ok] 诱饵文件 BAIT.txt / BAIT2.txt 完好（无覆盖）"
else
  echo "[!!!ESCAPE] 诱饵文件被改写"; ESCAPE=$((ESCAPE+1)); fi
# 根目录下是否出现逃逸产物
esc=$(find "$ROOT" -maxdepth 1 -name 'ESCAPED*' -o -maxdepth 1 -name 'pwn*' 2>/dev/null)
if [ -z "$esc" ]; then echo "[ok] 根目录无 ESCAPED*/pwn* 逃逸产物"; else echo "[!!!ESCAPE] $esc"; ESCAPE=$((ESCAPE+1)); fi
# .tmp 残留
tmpc=$(find "$W" -name '*.tmp' -o -name '*.dbkp-restore.tmp' 2>/dev/null | wc -l)
echo "[info] 临时/半成品残留数 = $tmpc"
# 0 字节箱
zero=$(find "$W/out" -type f -size 0 2>/dev/null | wc -l)
echo "[info] 0 字节产物数 = $zero"

echo ""
echo "==================== 汇总 ===================="
echo "TOTAL=$TOTAL  CRASH/HANG=$CRASH  SILENT-ACCEPT=$SILENT  ESCAPE=$ESCAPE"
echo "（SILENT-ACCEPT 中 expect=any 的用例属合法业务路径，需人工分辨）"
