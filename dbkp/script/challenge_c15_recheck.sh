#!/bin/bash
# 注意：此脚本用小文件(512KB)任务，执行快于提交，队列峰值 <8，故全 201、无 429。
#       真正验证 429 见 challenge_c15_slow.sh（16MB 慢任务）。保留本脚本作为"无背压场景下不误拒"的证据。
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_probe/challenge/c15"
CURL=/mingw64/bin/curl.exe
URL=http://127.0.0.1:18089
export CURL URL W
export TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login2.json")
export SRC='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/src'
export DST='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/out'
one() {
  code=$("$CURL" -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/recheck$1.dbkp\",\"label\":\"r$1\"}" \
    "$URL/api/jobs")
  echo "$code"
}
export -f one
echo "=== 100 个并发 POST（20 路并行，队列上限 8）==="
seq 1 100 | xargs -P 20 -I{} bash -c 'one {}' > "$W/stress2_codes.txt"
echo "HTTP 状态分布:"; sort "$W/stress2_codes.txt" | uniq -c
echo "=== 服务存活 + jobCount ==="
"$CURL" -s --max-time 5 "$URL/api/info" | head -c 300; echo
echo "=== 落盘归档数（应远小于 100）==="
find "$W/data/out" -name '*.dbkp' | wc -l
echo "=== 服务端 429 日志条数 ==="
grep -c "队列已满" "$W/server2.log"
