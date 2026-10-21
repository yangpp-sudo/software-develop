# dbkp —— 数据备份软件（命令行 `bk`）

纯 C++17、**零第三方库**的本地文件备份工具：备份/还原、自实现压缩与加密、
自实现哈希与口令派生、元数据保持、六维过滤、复制模式与定时备份。

## 1. 构建
```bash
# Linux / macOS（自动选 src/Platform/FS_posix.cpp）
make -j4            # 产出 bin/bk
make test           # 92 项单元测试

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

## 3. 测试与测量
| 目的 | 命令 | 当天实测 |
|---|---|---|
| 单元测试 | `powershell -File script/_verify.ps1 [-filter Meta]` | 92/92 通过 |
| 端到端 | `powershell -File script/e2e.ps1` | 19/19 通过（在临时沙箱内跑，自动清理） |
| 性能 | `powershell -File script/perf.ps1` | 见 `doc/perf-raw.txt`（lz77 31.7 MB/s，copy 111 MB/s） |

## 4. 目录结构
```
include/  Backup Codec Common Crypto Enumerator Pack Platform Utils
src/      同名实现 + main.cpp（7 个子命令）
test/     TestFramework.h（迷你 GoogleTest）+ 14 个测试文件
script/   e2e.ps1 / _verify.ps1 / perf.ps1 / demo.sh
doc/      01-需求分析说明书.md  02-系统设计说明书.md  03-测试报告.md  perf-raw.txt
```

## 5. 能力清单
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
- **中文**：Unicode 命令行取参 + UTF-8 控制台输出。

## 6. 已知限制
- AES 为查表实现，未做侧信道防护；RLE 对随机数据不压缩（但保证不膨胀）。
- 增量为**预留扩展**：记录里已含 `crc64/mtime/ino`，接口具备（见 `doc/02` 第 7 节）。
- 无图形界面（按"功能链完整度优先"取舍）。

详细设计见 `doc/02-系统设计说明书.md`，测试证据见 `doc/03-测试报告.md`。
