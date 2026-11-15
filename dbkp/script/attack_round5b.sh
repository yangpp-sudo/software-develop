#!/usr/bin/env bash
# 攻击轮 5b：修正轮5脚本bug（A1没真写、C4用错旗标），补加密箱扩展块篡改与新用例
set +e
ROOT=/c/Users/user/Desktop/develop/software-develop/dbkp
BK="C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\bin\\bk.exe"
RUN=$ROOT/runwin.exe
W=$ROOT/_attack5
CB=C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5
WS=$CB/src

TOTAL=0; CRASH=0; ESCAPE=0
bait_ok() {
  grep -q 'BAIT5-DO-NOT-TOUCH' "$W/BAIT.txt" && grep -q 'BAIT5B-DO-NOT-TOUCH' "$ROOT/BAIT5B.txt"
}
r5b() {
  local label="$1"; shift
  TOTAL=$((TOTAL+1))
  local out rc rx tag
  out=$(timeout 25 "$RUN" "$BK" "$@" 2>&1); rc=$?
  rx=$(echo "$out" | sed -n 's/.*\[runwin exit=\([0-9]*\)\].*/\1/p' | tail -1)
  tag="ok"
  if [ "$rc" -eq 124 ] || [ "${rx:-0}" -ge 3 ] 2>/dev/null || [ "$rc" -ge 3 ]; then
    tag="!!! CRASH/HANG"; CRASH=$((CRASH+1))
  fi
  printf '[%s] %-46s rc=%s rx=%s | %s\n' "$tag" "$label" "$rc" "${rx:-?}" "$(echo "$out" | tr -d '\000' | tr '\n' ' ' | cut -c1-100)"
  bait_ok || { echo "  !!! BAIT 被改写 !!!"; ESCAPE=$((ESCAPE+1)); }
}

PY="C:/Users/user/.workbuddy/binaries/python/versions/3.13.12/python.exe"

echo "================ A' 组: 真·魔数/真·扩展块篡改 ================"
# 真·错误魔数（这次真的写入 XXXX）
"$PY" - <<'PYEOF'
import os
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
d0 = open(os.path.join(base,'good.dbkp'),'rb').read()
b = bytearray(d0); b[0:4] = b'XXXX'
open(os.path.join(base,'a1r_badmagic.dbkp'),'wb').write(b); print('wrote a1r, magic now', bytes(b[:4]))
PYEOF
r5b "A1' 真错误魔数 verify(期望拒)" verify "$CB/arc/a1r_badmagic.dbkp"
r5b "A1'b 真错误魔数 restore(期望拒)" restore "$CB/arc/a1r_badmagic.dbkp" "$CB/out/a1r"
r5b "A1'c 真错误魔数 info(期望拒)" info "$CB/arc/a1r_badmagic.dbkp"

# 造 sha256 箱（hs=1024）与 aes256 箱（hs=1024）与 aes+sha 箱（hs=1536），逐个吞/谎扩展块
"$RUN" "$BK" backup "$WS" "$CB/arc/sha.dbkp" --checksum sha256 >/dev/null 2>&1
"$RUN" "$BK" backup "$WS" "$CB/arc/aes.dbkp" -c aes256 -p pw123 >/dev/null 2>&1
"$RUN" "$BK" backup "$WS" "$CB/arc/aessha.dbkp" -c aes256 -p pw123 --checksum sha256 >/dev/null 2>&1
"$PY" - <<'PYEOF'
import struct, os
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
def tweak(src, dst, newhs):
    d = bytearray(open(os.path.join(base,src),'rb').read())
    struct.pack_into('<H', d, 6, newhs)
    open(os.path.join(base,dst),'wb').write(d)
    print('tweak', src, '->', dst, 'hs=', newhs)
for src in ('sha.dbkp','aes.dbkp','aessha.dbkp'):
    tag = src.split('.')[0]
    tweak(src, tag+'_hs512.dbkp', 512)     # 吞扩展块
    tweak(src, tag+'_hs999.dbkp', 999)     # 非512倍数
    tweak(src, tag+'_hs1536.dbkp', 1536)   # 谎称多一块
PYEOF
for t in sha aes aessha; do
  r5b "${t}吞扩展块hs512(期望拒)" verify "$CB/arc/${t}_hs512.dbkp"
  r5b "${t}非倍数hs999(期望拒)" verify "$CB/arc/${t}_hs999.dbkp"
  r5b "${t}谎称多块hs1536(期望拒)" verify "$CB/arc/${t}_hs1536.dbkp"
done

echo "================ C' 组: 修正旗标后的口令/新用例 ================"
r5b "C4' =开头空格口令加密" backup "$WS" "$CB/arc/c4r.dbkp" -c aes256 -p "=pass word 123"
r5b "C4'b 同口令解密回读" restore "$CB/arc/c4r.dbkp" "$CB/out/c4r" -p "=pass word 123"
r5b "C4'c 错口令拒绝" restore "$CB/arc/c4r.dbkp" "$CB/out/c4wrong" -p "wrong pw"
r5b "C9 selftest 内置已知答案" selftest
r5b "C10 compare 归档vs源(应一致)" compare "$CB/arc/good.dbkp" "$CB/src"
# 篡改源文件后 compare 应检出差异
printf 'alpha bravo charlie TAMPERED' > "$W/src/a.txt"
r5b "C11 compare 源被篡改(应检出)" compare "$CB/arc/good.dbkp" "$CB/src"
printf 'alpha bravo charlie delta' > "$W/src/a.txt"  # 还原源
# skip-payload-verify 后逐条 CRC 仍应拦截翻转块
"$PY" - <<'PYEOF'
import os
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
d = bytearray(open(os.path.join(base,'good.dbkp'),'rb').read())
mid = len(d)//2
d[mid] ^= 0xFF
open(os.path.join(base,'flip1.dbkp'),'wb').write(d); print('flipped 1 byte at', mid)
PYEOF
r5b "C12 翻转1字节+skip-verify(逐条CRC拦截)" restore "$CB/arc/flip1.dbkp" "$CB/out/c12" --skip-payload-verify

echo "================ 汇总 ================"
echo "TOTAL=$TOTAL CRASH/HANG=$CRASH ESCAPE=$ESCAPE"
bait_ok && echo "BAIT=完好" || echo "BAIT=被改写!!!"
