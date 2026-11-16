#!/bin/bash
# C15 压力：100 个并发 POST，workers=1，看服务端是否无条件全收（无背压）
B=/c/Users/user/Desktop/develop/software-develop/dbkp
W="$B/_probe/challenge/c15"
CURL=/mingw64/bin/curl.exe
URL=http://127.0.0.1:18089
export CURL URL W
export TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$W/login.json")
export SRC='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/src'
export DST='C:/Users/user/Desktop/develop/software-develop/dbkp/_probe/challenge/c15/data/out'
one() {
  "$CURL" -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST \
    -H "Content-Type: application/json" -H "Authorization: Bearer $TOKEN" \
    -d "{\"type\":\"backup\",\"source\":\"$SRC\",\"destination\":\"$DST/pressure$1.dbkp\",\"label\":\"p$1\"}" \
    "$URL/api/jobs"
}
export -f one
echo "=== 100 个并发 POST（20 路并行）==="
seq 1 100 | xargs -P 20 -I{} bash -c 'one {}' > "$W/stress_codes.txt"
echo "HTTP 状态分布:"; sort "$W/stress_codes.txt" | uniq -c
echo "=== 服务端 jobCount ==="
"$CURL" -s --max-time 10 "$URL/api/info" | head -c 300; echo
