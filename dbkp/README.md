# dbkp —— 数据备份软件（命令行 `bk` + Web 服务 `bkd`）

纯 C++17、**零第三方库**的本地文件备份工具：备份/还原、自实现压缩与加密、
自实现哈希与口令派生、元数据保持、六维过滤、复制模式与定时备份；
同一套内核之上再包一层 HTTP/JSON + SSE 的本地 Web 界面（`bkd`）。

## 1. 构建
```bash
# Linux / macOS（自动选 src/Platform/FS_posix.cpp）
make -j4            # 产出 bin/bk 与 bin/bkd
make test           # 102 项单元测试

# Windows（MinGW-w64 g++ 8.1，自动选 FS_win.cpp）
mingw32-make -j4 all bin/bk_test.exe
```
对象文件统一落在 `obj/`，可执行文件在 `bin/`，`make clean` 双平台可用。

## 2. 一分钟演示
```bash
mkdir -p demo/sub && echo hello > demo/a.txt && echo world > demo/sub/b.log
bin/bk backup  demo  bk.dbkp  -a lzhuff -c aes256 -p 'S3cret!'   # 备份（压缩+加密）
bin/bk info     bk.dbkp -p 'S3cret!'                             # 条目数/压缩率
bin/bk verify    bk.dbkp -p 'S3cret!'                             # 自校验
bin/bk restore   bk.dbkp demo_out -p 'S3cret!' --force            # 还原
bin/bk compare   bk.dbkp demo                                      # 与源逐字节比对
bin/bk backup   demo demo_copy --copy                              # 复制模式（目录→目录）
bin/bk schedule demo sched_dir --every 10s --times 5 --keep 3       # 定时 + 保留 3 份
bin/bk selftest                                                    # 算法 known-answer 自检
```

## 3. Web 服务（`bkd`）
```powershell
# 只用一条命令起服务，浏览器打开 http://127.0.0.1:8080/
bin\bkd.exe --port 8080 --web web --data-root D:\sandbox --password 'S3cret!'
```
| 选项 | 含义 |
|---|---|
| `--host` | 默认 `127.0.0.1`；`0.0.0.0` 才会被局域网访问（风险自担） |
| `--data-root DIR` | 路径沙箱：所有备份/还原/浏览都不得越界；**不设 = 任意路径可读写** |
| `--password` / `--password-sha256` | 登录口令（或只存摘要）；两者都不给 = 免鉴权，仅建议本机调试 |
| `--token-ttl H` / `--secret S` | 令牌有效期（默认 12h）；固定密钥后重启服务旧令牌仍可用 |
| `--workers N` / `--max-body MB` | 并发任务数（1~8，默认 2）；请求体上限（默认 64MB） |
| `--no-static` / `--config FILE` / `--log-level L` | 只当 API 用 / JSON 配置 / `quiet|error|warn|info|debug` |

接口统一返回 `{"code":0,"msg":"ok","data":…}`，`code` 直接取自工程错误码表：
`/api/info`、`/api/login`、`/api/config`、`/api/browse`、`/api/stat`、
`/api/jobs`（GET 列表 / POST 建任务）、`/api/jobs/:id`（`?log=1` 带任务日志）、
`/api/jobs/:id/cancel`、`/api/events`（SSE：`hello`/`tick`/`done`/`ping`）、`/api/shutdown`。
网页能建备份/还原/校验任务、看实时进度与日志、取消任务、浏览并读归档卷标。

## 4. 测试与测量
| 目的 | 命令 | 当天实测 |
|---|---|---|
| 单元测试 | `powershell -File script/_verify.ps1 [-filter Meta]` | 102/102 通过 |
| 命令行端到端 | `powershell -File script/e2e.ps1` | 19/19 通过（在临时沙箱内跑，自动清理） |
| Web 端到端 | `powershell -File script/smoke_web.ps1` | 39/39 通过（自起自停 `bkd`，退出码 0 即全绿） |
| 性能 | `powershell -File script/perf.ps1` | 见 `doc/perf-raw.txt`（lz77 31.7 MB/s，copy 111 MB/s） |

## 5. 目录结构
```
include/  Backup Codec Common Crypto Enumerator Pack Platform Utils Web
src/      同名实现 + main.cpp（CLI，7 个子命令）+ server_main.cpp（bkd）
web/      index.html（单文件页面：内联 CSS/JS，fetch + EventSource，无前端依赖）
test/     TestFramework.h（迷你 GoogleTest）+ 15 个测试文件
script/   e2e.ps1 / _verify.ps1 / smoke_web.ps1 / perf.ps1 / demo.sh
doc/      01-需求分析说明书.md  02-系统设计说明书.md  03-测试报告.md  perf-raw.txt
```

## 6. 能力清单
- **备份/还原**：`.dbkp` 归档模式（自描述、可校验）与逐文件复制模式，互为补充。
- **压缩（自实现）**：Huffman（码长退化）、LZ77（滑窗 + nibble 打包）、RLE（v2 令牌，随机数据不膨胀）、LZ77→Huffman 级联。
- **加密（自实现）**：AES-256-CBC、ChaCha20、XOR（演示）；口令 → PBKDF2-HMAC-SHA256 → 主密钥包装 + Encrypt-then-HMAC 标签。
- **完整性**：记录级 CRC64（ECMA-182）、载荷 SHA-256、HMAC 口令校验，篡改单字节必被检出。
- **元数据**：类型/权限/属主/`mtime`·`atime`（纳秒）/`ctime`/inode/设备号/主从设备号；
  目录时间**逆序**回填，硬链接按 `(dev,ino)` 去重，符号链接存链接本身。
- **过滤（六维 AND）**：路径、名称、类型、修改时间、尺寸、属主；`--max-depth` 口径同 `find -maxdepth`。
- **超长路径**：归档侧 `X` 扩展记录（实测 444 字符相对路径完整往返）+
  Windows 侧 `\\?\` 突破 `MAX_PATH`（含 UNC 分支）。
- **跨平台**：Win32 与 POSIX 各自实现 `Platform::`，同一份上层代码。
- **中文**：Unicode 命令行取参 + UTF-8 控制台输出（`bk` 与 `bkd` 共用 `Platform/Args.h`）。
- **Web 界面**：`bkd` 提供 REST + SSE，浏览器里建任务/看进度/取消/读归档卷标；
  令牌无状态（HMAC 签名 + 过期时间）、路径沙箱、只默认绑回环；内核里零 HTTP 代码。

## 7. 已知限制
- AES 为查表实现，未做侧信道防护；RLE 对随机数据不压缩（但保证不膨胀）。
- 增量为**预留扩展**：记录里已含 `crc64/mtime/ino`，接口具备（见 `doc/02` 第 8 节）。
- 界面是浏览器页（`web/`：原生 HTML/JS + EventSource，无打包器、无第三方前端库），
  没有桌面 GUI。
- `bkd` 故意做小：每连接一线程、单请求单响应，**不实现 keep-alive 与 chunked 请求体**，
  够本机/局域网单人使用，不能当通用 Web 服务器。
- Web 的安全边界是"本机使用"：默认只绑 `127.0.0.1`；用 `--host 0.0.0.0` 时务必设
  `--password`，并清楚口令是明文走 HTTP 的（本程序不含 TLS，需要对公网暴露请置于反代之后）。

详细设计见 `doc/02-系统设计说明书.md`，测试证据见 `doc/03-测试报告.md`。
