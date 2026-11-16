#!/bin/bash
# C15 正确版：登录 -> Bearer token -> 连续 20 次 POST /api/jobs -> 检查队列与进程存活
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_probe/challenge/c15"
CURL=/mingw64/bin/curl.exe
URL=http://127.0.0.1:18089
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login.json")
SRC='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/src'
DST='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/out'

echo "token=${TOKEN:0:20}...(已取到)"
if [ -z "$TOKEN" ]; then echo "NO_TOKEN"; exit 9; fi

echo "=== 无 token 提交（应 401）==="
"$CURL" -s -o "$W/noauth.txt" -w "http=%{http_code}\n" --max-time 5 -X POST -H "Content-Type: application/json" \
  -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/noauth.dbkp\"}" "$URL/api/jobs"
cat "$W/noauth.txt"; echo

echo "=== 20 次带 token 提交 ==="
ok=0; rej=0
for i in $(seq 1 20); do
    code=$("$CURL" -s -o "$W/job_$i.json" -w "%{http_code}" --max-time 10 -X POST \
      -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
      -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/job$i.dbkp\",\"label\":\"c15-$i\"}" \
      "$URL/api/jobs")
    if [ "$code" = "201" ]; then ok=$((ok+1)); else rej=$((rej+1)); echo "  #$i http=$code body=$(cat "$W/job_$i.json" | head -c 200)"; fi
    if [ $((i % 5)) -eq 0 ]; then echo "  ...已发 $i 条 (201=$ok 其他=$rej)"; fi
done
echo "汇总: 201=$ok 其他=$rej"

echo "=== GET /api/jobs 队列状态 ==="
"$CURL" -s --max-time 5 -H "Authorization: Bearer $TOKEN" "$URL/api/jobs" > "$W/jobs.json"
head -c 1200 "$W/jobs.json"; echo
echo "=== /api/info 存活检查 ==="
"$CURL" -s --max-time 5 "$URL/api/info" | head -c 400; echo
