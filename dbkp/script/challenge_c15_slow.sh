#!/bin/bash
# C15 API 层 429 复测：16MB 慢任务 + 顺序连发，队列上限 8 应触发显式拒绝
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_probe/challenge/c15"
CURL=/mingw64/bin/curl.exe
URL=http://127.0.0.1:18089
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login2.json")
SRC='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/src'
DST='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/out'

echo "=== 顺序连发 24 个慢任务（队列上限 8）==="
ok=0; busy=0; other=0
for i in $(seq 1 24); do
    out=$("$CURL" -s --max-time 30 -w '\n%{http_code}' -X POST \
      -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
      -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/slow$i.dbkp\",\"label\":\"s$i\"}" \
      "$URL/api/jobs")
    code=$(printf '%s' "$out" | tail -1)
    body=$(printf '%s' "$out" | head -1)
    case "$code" in
        201) ok=$((ok+1)) ;;
        429) busy=$((busy+1)); if [ "$busy" -eq 1 ]; then echo "  首个 429 响应体: $body"; fi ;;
        *)   other=$((other+1)); echo "  #$i http=$code body=$body" ;;
    esac
    if [ $((i % 6)) -eq 0 ]; then echo "  ...已发 $i 条 (201=$ok 429=$busy 其他=$other)"; fi
done
echo "汇总: 201=$ok  429=$busy  其他=$other"
echo "=== 服务存活 ==="
"$CURL" -s --max-time 5 "$URL/api/info" | head -c 260; echo
echo "=== 服务端 429 日志 ==="; grep -c "队列已满" "$W/server2.log"
