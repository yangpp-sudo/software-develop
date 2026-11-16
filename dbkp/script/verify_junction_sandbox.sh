#!/bin/bash
# 手工端到端验证：data-root 内放 junction 指向围栏外，Web 沙箱必须拒绝
# 与单测框架完全独立，不依赖 bk_test_current.exe
B=/c/Users/user/Desktop/develop/software-develop/dbkp
CB=C:/Users/user/Desktop/develop/software-develop/dbkp
W=$B/_jct
CW=$CB/_jct
PY=/c/Users/user/AppData/Local/Programs/Python/Python36/python.exe
CURL=/mingw64/bin/curl.exe
PORT=19095
URL=http://127.0.0.1:$PORT

cd "$B" || exit 1
MSYS_NO_PATHCONV=1 taskkill /F /IM bkd.exe >/dev/null 2>&1

# 先摘掉可能残留的 junction，绝不顺着链接删目标
"$PY" -c "import os; p=r'$CW/data/evil'; os.rmdir(p) if os.path.isdir(p) else None" 2>/dev/null
rm -rf "$W"
mkdir -p "$W/data" "$W/outside"
echo "SECRET-OUTSIDE-9999" > "$W/outside/secret.txt"
echo "INSIDE" > "$W/data/ok.txt"

echo "=== 1. 创建 junction: data/evil -> outside ==="
"$PY" -c "import _winapi; _winapi.CreateJunction(r'$CW/outside', r'$CW/data/evil'); print('CreateJunction OK')"
echo "=== 2. 确认它确实是 reparse point ==="
"$PY" -c "
import ctypes
p=r'$CW\data\evil'
a=ctypes.windll.kernel32.GetFileAttributesW(p)
print('GetFileAttributesW=',hex(a),' REPARSE_POINT=',bool(a & 0x400))
import os
print('经链接能读到围栏外文件:', open(p+r'\secret.txt').read().strip())
"

echo "=== 3. 启动 bkd（data-root = _jct/data） ==="
(./bin/bkd.exe --host 127.0.0.1 --port $PORT --web "$CB/web" \
  --data-root "$CW/data" --password jctpw --max-body 1 --workers 2 \
  --max-pending 8 --log-level error > "$W/server.log" 2>&1 &)
ready=
for i in $(seq 1 50); do
  c=$("$CURL" -s -o /dev/null -w "%{http_code}" --max-time 2 "$URL/api/info" 2>/dev/null)
  [ "$c" = "200" ] && { ready=1; break; }
  sleep 0.2
done
echo "  /api/info ready=$c (ready_flag=$ready)"

"$CURL" -s -o "$CW/login.json" -w "  login http=%{http_code}\n" --max-time 5 \
  -X POST -H "Content-Type: application/json" -d '{"password":"jctpw"}' "$URL/api/login"
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login.json")
echo "  token_len=${#TOKEN}"
AUTH="Authorization: Bearer $TOKEN"

echo "=== 4. /api/browse（关键：evil 必须 403） ==="
for q in "." "ok.txt" "evil" "evil/secret.txt" "../outside"; do
  code=$("$CURL" -s -o "$CW/r.json" -w "%{http_code}" --max-time 5 \
    -H "$AUTH" "$URL/api/browse?path=$q")
  body=$(head -c 110 "$W/r.json" | tr -d '\000')
  echo "  path=$q -> http=$code  body=$body"
done

echo "=== 5. POST /api/jobs（source 经 junction 越界，必须 4xx） ==="
code=$("$CURL" -s -o "$CW/j.json" -w "%{http_code}" --max-time 5 -X POST \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d "{\"type\":\"backup\",\"source\":\"evil\",\"destination\":\"out.dbkp\"}" "$URL/api/jobs")
echo "  source=evil -> http=$code  body=$(head -c 160 "$W/j.json" | tr -d '\000')"

echo "=== 6. 关闭服务并清理（先摘 junction 再删树） ==="
"$CURL" -s -o /dev/null --max-time 5 -X POST -H "$AUTH" "$URL/api/shutdown"
sleep 1
MSYS_NO_PATHCONV=1 taskkill /F /IM bkd.exe >/dev/null 2>&1
"$PY" -c "import os; os.rmdir(r'$CW/data/evil'); print('junction removed')" 2>&1
echo "  围栏外文件仍在: $(cat "$W/outside/secret.txt")"
echo VERIFY_DONE
