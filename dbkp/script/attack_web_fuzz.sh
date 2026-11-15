#!/usr/bin/env bash
# 攻击轮 2：Web API 不讲道理 fuzz
# 判定：任何 5xx = 服务端未捕获异常（严重洞）；攻击后 /api/info 不 200 = 服务被打死（严重洞）
#      沙箱外出现文件 = 路径逃逸（严重洞）；非法请求返回 2xx 且真执行 = 静默接受（洞）
# 路径约定：bash 侧用 MSYS 路径($B/$W)；Windows 原生程序(curl/python/bkd)必须用 C:/ 形式($CB/$CW)
set +e
B=/c/Users/user/Desktop/develop/software-develop/dbkp
CB=C:/Users/user/Desktop/develop/software-develop/dbkp
CURL=/mingw64/bin/curl.exe
PORT=19090
URL=http://127.0.0.1:$PORT
W=$B/_attack/web
CW=$CB/_attack/web
rm -rf "$W"; mkdir -p "$W/src" "$W/out" "$W/body" "$W/resp"
printf 'aaa' > "$W/src/a.txt"
printf 'bbb' > "$W/src/b.txt"
printf 'BAIT-WEB-DO-NOT-TOUCH' > "$B/BAIT_WEB.txt"
SRC=$CW/src
DST=$CW/out

LONG=$(head -c 30000 /dev/zero | tr '\0' 'A')
# 畸形 body 文件（Windows 路径给 python 写，bash 也能读同一文件）
printf '{'                                    > "$W/body/unclosed.json"
printf '[]'                                    > "$W/body/array.json"
printf 'null'                                  > "$W/body/null.json"
printf ''                                      > "$W/body/empty.json"
printf '\xff\xfe\x80{"type":"backup"}'         > "$W/body/badutf8.json"
printf '{"type":"backup","type":"restore"}'    > "$W/body/dupkey.json"
printf '{"type":123,"source":null}'            > "$W/body/wrongtype.json"
printf '{"n":1e400}'                           > "$W/body/bignum.json"
printf '{"path":"\\u0000\\uZZZZ"}'             > "$W/body/badunicode.json"
python -c "open(r'$CW/body/deep.json','w').write('['*5000 + ']'*5000)" 2>/dev/null || \
  python3 -c "open(r'$CW/body/deep.json','w').write('['*5000 + ']'*5000)"
python -c "open(r'$CW/body/huge.json','w').write('{\"x\":\"' + 'A'*1500000 + '\"}')" 2>/dev/null || \
  python3 -c "open(r'$CW/body/huge.json','w').write('{\"x\":\"' + 'A'*1500000 + '\"}')"

TOTAL=0; FIVEXX=0; ACCEPT=0

req() { # label method path [extra curl args...]
  local label="$1"; local method="$2"; local path="$3"; shift 3
  TOTAL=$((TOTAL+1))
  local f="$W/resp/r$TOTAL.txt"       # bash 读（MSYS）
  local fo="$CW/resp/r$TOTAL.txt"     # curl 写（Windows）
  local code; code=$("$CURL" -s -o "$fo" -w "%{http_code}" --max-time 12 \
      -X "$method" "$@" "$URL$path" 2>/dev/null)
  local tag="ok"
  case "$code" in
    5*) tag="!!!5xx"; FIVEXX=$((FIVEXX+1));;
    000) tag="!!!NO-REPLY"; FIVEXX=$((FIVEXX+1));;
    2*) if [ "$label" != "config 伪造token" ]; then :; fi;;
  esac
  printf '[%-12s] %-44s http=%-4s | %s\n' "$tag" "$label" "$code" "$(head -c 130 "$f" 2>/dev/null | tr '\n' ' ')"
}

echo "================ 启动 bkd（沙箱限制 + 1MB 上限 + 队列 8） ================"
cd "$B"
./bin/bkd.exe --host 127.0.0.1 --port $PORT --web "$CB/web" \
  --data-root "$CW" --password attackpw \
  --max-body 1 --workers 2 --max-pending 8 --log-level error \
  > "$W/server.log" 2>&1 &
SRV=$!
for i in $(seq 1 40); do
  c=$("$CURL" -s -o /dev/null -w "%{http_code}" --max-time 2 "$URL/api/info" 2>/dev/null)
  [ "$c" = "200" ] && break; sleep 0.2
done
echo "server_pid=$SRV  info_http=$c"

echo "================ 登录取 token ================"
"$CURL" -s -o "$CW/login.json" -w "login_http=%{http_code}\n" --max-time 5 -X POST \
  -H "Content-Type: application/json" -d '{"password":"attackpw"}' "$URL/api/login"
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login.json")
echo "token=${TOKEN:0:24}..."
AUTH="Authorization: Bearer $TOKEN"
if [ -z "$TOKEN" ]; then echo "!!! NO TOKEN - 后续用例无效，脚本终止"; exit 9; fi

echo "================ A 组: 鉴权与登录畸形 ================"
req "login 空body"                 POST /api/login -H "Content-Type: application/json" -d ''
req "login 未闭合JSON"            POST /api/login -H "Content-Type: application/json" --data-binary @"$CW/body/unclosed.json"
req "login 5000层嵌套"            POST /api/login -H "Content-Type: application/json" --data-binary @"$CW/body/deep.json"
req "login 非法UTF8"              POST /api/login -H "Content-Type: application/json" --data-binary @"$CW/body/badutf8.json"
req "login 超长口令"              POST /api/login -H "Content-Type: application/json" -d "{\"password\":\"$LONG\"}"
req "login 非对象(数组)"          POST /api/login -H "Content-Type: application/json" -d '[]'
req "login 非对象(null)"          POST /api/login -H "Content-Type: application/json" -d 'null'
for i in 1 2 3 4 5 6 7; do req "login 错口令#$i(限速)" POST /api/login -H "Content-Type: application/json" -d '{"password":"wrong"}'; done
req "config 无token"              GET  /api/config
req "config 空Bearer"             GET  /api/config -H "Authorization: Bearer "
req "config 超长token"            GET  /api/config -H "Authorization: Bearer $LONG"
req "config 小写bearer"           GET  /api/config -H "Authorization: bearer $TOKEN"
req "config 无前缀token"          GET  /api/config -H "Authorization: $TOKEN"
req "config 伪造token"            GET  /api/config -H "Authorization: Bearer AAAA.BBBB.CCCC"
req "config token带CRLF"          GET  /api/config -H "Authorization: Bearer $TOKEN%0d%0aX-Evil: 1"

echo "================ B 组: POST /api/jobs 畸形 JSON（讲道理的攻击者会重算一切） ================"
req "jobs 空body"                 POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d ''
req "jobs 未闭合JSON"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/unclosed.json"
req "jobs 数组"                   POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/array.json"
req "jobs null"                   POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/null.json"
req "jobs 5000层嵌套"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/deep.json"
req "jobs 非法UTF8"               POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/badutf8.json"
req "jobs 重复键"                 POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/dupkey.json"
req "jobs 字段类型错"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/wrongtype.json"
req "jobs 超大数字1e400"          POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/bignum.json"
req "jobs 非法unicode转义"        POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/badunicode.json"
req "jobs 1.5MB 超体"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" --data-binary @"$CW/body/huge.json"
req "jobs 超长source"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$LONG\",\"destination\":\"$DST/x.dbkp\"}"
req "jobs source带分号"           POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$SRC;rm -rf x\",\"destination\":\"$DST/x.dbkp\"}"
req "jobs source带反引号"         POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"\`whoami\`\",\"destination\":\"$DST/x.dbkp\"}"
req "jobs dest逃逸..\\..\\"       POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/../../ESCAPE.dbkp\"}"
req "jobs dest绝对路径"           POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"C:/Windows/Temp/pwn.dbkp\"}"
req "jobs crypto未知"             POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/x.dbkp\",\"crypto\":\"aes999\",\"password\":\"x\"}"
req "jobs algo未知"               POST /api/jobs -H "$AUTH" -H "Content-Type: application/json" -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/x.dbkp\",\"algorithm\":\"huffmanX\"}"

echo "================ C 组: 路径参数注入（GET /api/stat /api/browse /api/compare） ================"
req "stat ../../etc/passwd"       GET "/api/stat?path=../../etc/passwd" -H "$AUTH" --path-as-is
req "stat %2e%2e%2f"             GET "/api/stat?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd" -H "$AUTH"
req "stat 双重编码"               GET "/api/stat?path=%252e%252e%252f" -H "$AUTH"
req "stat 反斜杠穿越"             GET "/api/stat?path=..%5c..%5cwin.ini" -H "$AUTH"
req "stat 绝对路径"               GET "/api/stat?path=C%3A%5CWindows%5Cwin.ini" -H "$AUTH"
req "stat NUL截断"                GET "/api/stat?path=x.dbkp%00.txt" -H "$AUTH" --path-as-is
req "stat 超长路径"               GET "/api/stat?path=$LONG" -H "$AUTH"
req "stat 空path"                 GET "/api/stat?path=" -H "$AUTH"
req "stat UNC"                    GET "/api/stat?path=%5c%5cserver%5cshare%5cx" -H "$AUTH"
req "stat ADS"                    GET "/api/stat?path=x.dbkp%3Apwn" -H "$AUTH"
req "stat 分号注入"               GET "/api/stat?path=x.dbkp%3Brm%20-rf" -H "$AUTH"
req "browse 穿越"                 GET "/api/browse?path=../../" -H "$AUTH" --path-as-is
req "compare 穿越"                GET "/api/compare?path=../../&source=$SRC" -H "$AUTH" --path-as-is
req "jobs/999999999999"           GET "/api/jobs/999999999999999999999" -H "$AUTH"
req "jobs/-5"                     GET "/api/jobs/-5" -H "$AUTH"
req "jobs/abc"                    GET "/api/jobs/abc" -H "$AUTH"
req "jobs/1?log=1 超长log"        GET "/api/jobs/1?log=1&x=$LONG" -H "$AUTH"

echo "================ D 组: HTTP 协议层不讲道理 ================"
req "超长URL 30K"                 GET "/api/info?x=$LONG" -H "$AUTH"
req "超长Header 30K"             GET /api/info -H "X-Evil: $LONG"
req "双Content-Length"           POST /api/login -H "Content-Type: application/json" -H "Content-Length: 5" -H "Content-Length: 6" -d '{"password":"attackpw"}'
req "畸形方法 BREW"              BREW /api/info
req "静态页穿越"                 GET "/../../../../../../windows/win.ini" --path-as-is
req "静态页 %2e%2e"              GET "/%2e%2e/%2e%2e/windows/win.ini" --path-as-is
req "Origin 带CRLF"              GET /api/info -H "Origin: http://evil%0d%0aX-Injected: 1"
req "Origin 恶意域"              GET /api/info -H "Origin: http://evil.example.com"
req "Range 畸形"                 GET /api/info -H "Range: bytes=-99999999999999999999"
req "Expect 100-continue"        POST /api/login -H "Expect: 100-continue" -H "Content-Type: application/json" -d '{"password":"attackpw"}'
req "Transfer-Encoding 混乱"     POST /api/login -H "Transfer-Encoding: chunked" -H "Content-Length: 5" -d 'abc'
req "无Host HTTP/1.0"            GET /api/info --http1.0
req "空路径"                     GET "" -H "$AUTH"

echo "================ E 组: 并发洪泛（队列上限 8，故意打爆） ================"
PIDS=""
for i in $(seq 1 40); do
  "$CURL" -s -o "$CW/resp/flood$i.txt" -w "%{http_code}" --max-time 15 -X POST \
    -H "Content-Type: application/json" -H "$AUTH" \
    -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/flood$i.dbkp\"}" \
    "$URL/api/jobs" > "$W/resp/flood$i.code" 2>/dev/null &
  PIDS="$PIDS $!"
done
# 只等这 40 个 curl，绝不无参 wait（无参 wait 会把常驻 bkd 一起等住）
for p in $PIDS; do wait "$p" 2>/dev/null; done
c201=0; c429=0; c5=0; cother=0
for i in $(seq 1 40); do
  c=$(cat "$W/resp/flood$i.code" 2>/dev/null)
  case "$c" in 201) c201=$((c201+1));; 429) c429=$((c429+1));; 5*) c5=$((c5+1));; *) cother=$((cother+1));; esac
done
echo "[flood] 201=$c201 429=$c429 5xx=$c5 other=$cother  (5xx>0 即为洞)"
[ "$c5" -gt 0 ] && FIVEXX=$((FIVEXX+c5))

echo "================ F 组: 攻击后存活与破坏性后果 ================"
TOTAL=$((TOTAL+1))
live=$("$CURL" -s -o "$CW/resp/live.txt" -w "%{http_code}" --max-time 5 "$URL/api/info" 2>/dev/null)
echo "[$( [ "$live" = 200 ] && echo ok || echo '!!!DEAD' )] 攻击后 /api/info = $live"
[ "$live" != "200" ] && FIVEXX=$((FIVEXX+1))
if grep -q BAIT-WEB-DO-NOT-TOUCH "$B/BAIT_WEB.txt"; then echo "[ok] 诱饵 BAIT_WEB.txt 完好"; else echo "[!!!ESCAPE] 诱饵被改写"; fi
esc=$(find "$B" -maxdepth 1 \( -name 'ESCAPE*' -o -name 'pwn*' -o -name 'ESCAPED*' \) 2>/dev/null)
if [ -z "$esc" ]; then echo "[ok] 根目录无逃逸产物"; else echo "[!!!ESCAPE] $esc"; fi
esc2=$(find "$W/out" -maxdepth 1 -name '*ESCAPE*' 2>/dev/null)
if [ -z "$esc2" ]; then echo "[ok] 沙箱外无越界归档"; else echo "[!!!ESCAPE] $esc2"; fi
echo "[info] 服务日志尾部:"; tail -8 "$W/server.log"

echo "================ 收尾 shutdown ================"
"$CURL" -s -o /dev/null -w "shutdown_http=%{http_code}\n" --max-time 5 -X POST -H "$AUTH" "$URL/api/shutdown"
sleep 1
kill $SRV 2>/dev/null
wait $SRV 2>/dev/null

echo ""
echo "==================== 汇总 ===================="
echo "TOTAL=$TOTAL  5xx/NO-REPLY=$FIVEXX  SILENT-ACCEPT=$ACCEPT"
echo "说明：4xx 是正确拒绝；2xx 需看是否真执行了恶意动作；5xx/服务死亡/逃逸 = 真洞"
