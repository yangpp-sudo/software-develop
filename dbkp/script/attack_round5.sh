#!/usr/bin/env bash
# 攻击轮 5：归档头字段定向魔改 / 文件系统新形态 / CLI 调度边界 —— 与轮1~4 用例不重叠
# 判定：runwin exit>=3 或 timeout=124 => 崩溃或挂起；BAIT 被改写 => 逃逸
set +e
ROOT=/c/Users/user/Desktop/develop/software-develop/dbkp
BK="C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\bin\\bk.exe"
RUN=$ROOT/runwin.exe
W=$ROOT/_attack5
CB=C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5
WS=$CB/src

rm -rf "$W"; mkdir -p "$W/src/sub" "$W/out" "$W/arc"
printf 'alpha bravo charlie delta' > "$W/src/a.txt"
printf 'echo foxtrot' > "$W/src/b.txt"
mkdir -p "$W/src/sub/deep"
printf 'golf hotel' > "$W/src/sub/deep/c.txt"
printf 'BAIT5-DO-NOT-TOUCH' > "$W/BAIT.txt"
printf 'BAIT5B-DO-NOT-TOUCH' > "$ROOT/BAIT5B.txt"

TOTAL=0; CRASH=0; ESCAPE=0
bait_ok() {
  grep -q 'BAIT5-DO-NOT-TOUCH' "$W/BAIT.txt" && grep -q 'BAIT5B-DO-NOT-TOUCH' "$ROOT/BAIT5B.txt"
}
r5() {
  local label="$1"; shift
  TOTAL=$((TOTAL+1))
  local out rc rx tag
  out=$(timeout 25 "$RUN" "$BK" "$@" 2>&1); rc=$?
  rx=$(echo "$out" | sed -n 's/.*\[runwin exit=\([0-9]*\)\].*/\1/p' | tail -1)
  tag="ok"
  if [ "$rc" -eq 124 ] || [ "${rx:-0}" -ge 3 ] 2>/dev/null || [ "$rc" -ge 3 ]; then
    tag="!!! CRASH/HANG"; CRASH=$((CRASH+1))
  fi
  printf '[%s] %-44s rc=%s rx=%s | %s\n' "$tag" "$label" "$rc" "${rx:-?}" "$(echo "$out" | tr '\n' ' ' | cut -c1-100)"
  bait_ok || { echo "  !!! BAIT 被改写 !!!"; ESCAPE=$((ESCAPE+1)); }
}

echo "================ 参照归档 ================"
"$RUN" "$BK" backup "$WS" "$CB/arc/good.dbkp" > /dev/null 2>&1
GMSYS=$W/arc/good.dbkp
echo "good.dbkp size=$(wc -c < "$GMSYS")"

echo "================ A 组: 头字段定向魔改（python 定位写入） ================"
PY="C:/Users/user/.workbuddy/binaries/python/versions/3.13.12/python.exe"
"$PY" - <<'PYEOF'
import struct, io
p = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc/good.dbkp'
d = open(p,'rb').read()
print('magic=%s head64=%s' % (d[:4], d[:64].hex()))
# 找 payloadOffset / recordCount / kdfRounds 等字段：dump 头 64 字节按小端 u32/u16 网格
for off in range(0, 64, 4):
    v32 = struct.unpack_from('<I', d, off)[0]
    v16a, v16b = struct.unpack_from('<HH', d, off)
    print('off=%02d u32=%-12u u16=%d,%d' % (off, v32, v16a, v16b))
PYEOF
echo "--- 以上为字段侦察，下面定向魔改 ---"

"$PY" - <<'PYEOF'
import struct, os, shutil
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
src = os.path.join(base,'good.dbkp')
d0 = open(src,'rb').read()
def w(name, offs, vals):
    b = bytearray(d0)
    for o,v in zip(offs, vals):
        if v is None: continue
        if isinstance(v,int):
            struct.pack_into('<I', b, o, v)
        else:
            b[o:o+len(v)] = v
    open(os.path.join(base,name),'wb').write(b)
    print('wrote', name)
# 侦察后的字段修改（off 由上一步输出人工确认；魔数固定 0..3）
w('a1_badmagic.dbkp', [(0, b'XXXX')], [None])
PYEOF

# A1 错误魔数
r5 "A1 魔数改成XXXX后verify" verify "$CB/arc/a1_badmagic.dbkp"
r5 "A1b 错误魔数后restore" restore "$CB/arc/a1_badmagic.dbkp" "$CB/out/a1"

# A2/A3 headerSize 字段（offset 6..7，u16）谎称有/无扩展块
"$PY" - <<'PYEOF'
import struct, os
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
d0 = open(os.path.join(base,'good.dbkp'),'rb').read()
b1 = bytearray(d0); struct.pack_into('<H', b1, 6, 65535)   # headerSize=0xFFFF（非512倍数，超大）
open(os.path.join(base,'a2_hs65535.dbkp'),'wb').write(b1)
b2 = bytearray(d0); struct.pack_into('<H', b2, 6, 1024)    # 谎称有扩展块但文件没那么多字节
open(os.path.join(base,'a3_hs1024.dbkp'),'wb').write(b2)
b3 = bytearray(d0); struct.pack_into('<H', b3, 6, 512)     # 谎称无扩展块（真实=1024，sha256箱）
open(os.path.join(base,'a4_hs512.dbkp'),'wb').write(b3)
print('ok')
PYEOF
r5 "A2 headerSize=0xFFFF verify" verify "$CB/arc/a2_hs65535.dbkp"
r5 "A2b headerSize=0xFFFF restore" restore "$CB/arc/a2_hs65535.dbkp" "$CB/out/a2"
r5 "A3 headerSize=1024谎称扩展块" verify "$CB/arc/a3_hs1024.dbkp"
r5 "A4 headerSize=512吞扩展块" verify "$CB/arc/a4_hs512.dbkp"

# A5 recordCount / payloadOffset / kdfRounds / cryptoAlg 定位修改
"$PY" - <<'PYEOF'
import struct, os
base = r'C:/Users/user/Desktop/develop/software-develop/dbkp/_attack5/arc'
d0 = open(os.path.join(base,'good.dbkp'),'rb').read()
# 侦察：找载荷区起点（记录区第一条 magic 0x4B434E44 或全零段后的记录），此处用物理事实：
# 文件尾部含 payload CRC；直接暴力：把每个 u32 字段逐个改成 0xFFFFFFFF 存档，共 N 份太贵。
# 改为只动两个最关键：u32 字段中出现 (值==512 或 1024 或 1536) 且位于 8..31 的 => payloadOffset 候选
cands=[]
for off in range(8, 40, 4):
    v = struct.unpack_from('<I', d0, off)[0]
    if v in (512,1024,1536) and v < len(d0):
        cands.append((off,v))
print('payloadOffset 候选:', cands)
if cands:
    off,orig = cands[0]
    b = bytearray(d0); struct.pack_into('<I', b, off, 0xFFFF0000)  # 4GB 外
    open(os.path.join(base,'a5_po_huge.dbkp'),'wb').write(b)
    b2 = bytearray(d0); struct.pack_into('<I', b2, off, orig+512)  # 错位一个块
    open(os.path.join(base,'a6_po_shift.dbkp'),'wb').write(b2)
    print('wrote a5/a6 with po at', off, orig)
# kdfRounds 候选：u32 == 4096 且 off 在 8..47
for off in range(8, 48, 4):
    v = struct.unpack_from('<I', d0, off)[0]
    if v == 4096:
        b = bytearray(d0); struct.pack_into('<I', b, off, 0)
        open(os.path.join(base,'a7_kdf0.dbkp'),'wb').write(b)
        print('wrote a7 kdf0 at', off)
        break
PYEOF
r5 "A5 payloadOffset=0xFFFF0000" verify "$CB/arc/a5_po_huge.dbkp" 2>/dev/null || true
r5 "A6 payloadOffset错位+512" verify "$CB/arc/a6_po_shift.dbkp" 2>/dev/null || true
# 错口令归档 + kdfRounds=0（若加密归档存在才测）
if [ -f "$W/arc/a7_kdf0.dbkp" ]; then
  r5 "A7 kdfRounds=0 verify" verify "$CB/arc/a7_kdf0.dbkp"
  r5 "A7b kdfRounds=0 restore" restore "$CB/arc/a7_kdf0.dbkp" "$CB/out/a7"
fi

echo "================ B 组: 文件系统新形态 ================"
# B1 大小写不同名两文件（Windows 大小写不敏感的恢复冲突）
mkdir -p "$W/srccase"
printf 'lower' > "$W/srccase/key.txt"
printf 'UPPER' > "$W/srccase/KEY.txt"
r5 "B1 大小写冲突对备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srccase" "$CB/arc/b1.dbkp"
r5 "B1b 大小写冲突对还原" restore "$CB/arc/b1.dbkp" "$CB/out/b1"
r5 "B1c 大小写冲突对verify" verify "$CB/arc/b1.dbkp"
# B2 硬链接
mkdir -p "$W/srchard"
printf 'harddata' > "$W/srchard/real.txt"
MSYS_NO_PATHCONV=1 cmd //c "mklink /H C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srchard\\hard.txt C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srchard\\real.txt" >/dev/null 2>&1
r5 "B2 含硬链接目录备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srchard" "$CB/arc/b2.dbkp"
r5 "B2b 含硬链接还原" restore "$CB/arc/b2.dbkp" "$CB/out/b2"
# B3 ADS（Zone.Identifier）
mkdir -p "$W/srcads"
printf 'adsfile' > "$W/srcads/doc.txt"
MSYS_NO_PATHCONV=1 cmd //c "echo blocked > C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srcads\\doc.txt:Zone.Identifier" >/dev/null 2>&1
r5 "B3 含ADS流文件备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srcads" "$CB/arc/b3.dbkp"
r5 "B3b 含ADS还原" restore "$CB/arc/b3.dbkp" "$CB/out/b3"
# B4 隐藏+系统属性文件
mkdir -p "$W/srchid"
printf 'hid' > "$W/srchid/secret.txt"
MSYS_NO_PATHCONV=1 attrib +H +S "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srchid\\secret.txt" >/dev/null 2>&1
r5 "B4 隐藏+系统属性文件备份" backup "C:\\Users\\user\\Desktop\\develop\\software-develop\\dbkp\\_attack5\\srchid" "$CB/arc/b4.dbkp"
r5 "B4b 隐藏+系统属性还原" restore "$CB/arc/b4.dbkp" "$CB/out/b4"
# B5 目标归档落在源目录内部
r5 "B5 目标=源目录内部.dbkp" backup "$WS" "$CB/src/inner.dbkp"
# B6 源是单个文件而非目录
r5 "B6 源=单个文件" backup "$CB/src/a.txt" "$CB/arc/b6.dbkp"

echo "================ C 组: CLI 调度与还原边界 ================"
r5 "C1 --times 0 定时备份" schedule --every 1s --times 0 --keep 2 "$WS" "$CB/arc/c1" 
r5 "C2 --every 0s" schedule --every 0s --times 1 --keep 2 "$WS" "$CB/arc/c2"
r5 "C3 --keep 0" schedule --every 1s --times 1 --keep 0 "$WS" "$CB/arc/c3"
r5 "C3b --keep -3" schedule --every 1s --times 1 --keep -3 "$WS" "$CB/arc/c3b"
r5 "C4 口令以=开头含空格" backup "$WS" "$CB/arc/c4.dbkp" -x aes256 -p "=pass word 123"
r5 "C4b 口令=开头解密回读" restore "$CB/arc/c4.dbkp" "$CB/out/c4" -p "=pass word 123"
r5 "C5 verify 传目录" verify "$CB/src"
r5 "C6 restore 目标=已存在文件" restore "$CB/arc/good.dbkp" "$CB/src/a.txt"
r5 "C7 --every 500ms 非整秒" schedule --every 500ms --times 1 --keep 2 "$WS" "$CB/arc/c7"
r5 "C8 --every 0.5s 小数秒" schedule --every 0.5s --times 1 --keep 2 "$WS" "$CB/arc/c8"

echo "================ 汇总 ================"
echo "TOTAL=$TOTAL CRASH/HANG=$CRASH ESCAPE=$ESCAPE"
ls -la "$W/out" | head -5
echo "=== 沙箱外逃逸检查 ==="
ls "$ROOT" | grep -v -E '^(bin|doc|include|objg|objut|objcov|script|src|test|web|_probe|_attack|_attack2|_attack5|_b6_tamper|_globtest|_ut|runwin|Makefile|README|BAIT)' || echo "无意外产物"
bait_ok && echo "BAIT=完好" || echo "BAIT=被改写!!!"
