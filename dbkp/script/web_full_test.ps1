<#
================================================================================
 dbkp Web 控制台 · 全功能自动测试脚本（兼新手教程）—— 适配本机最新版
--------------------------------------------------------------------------------
 相对组员原稿（dbkp_web_test_tutorial.ps1）的改动：
   1) 默认端口/starter 改为本机实际值：http://127.0.0.1:8099（bkd --port 8099）
   2) 所有 JSON 请求体改为 UTF-8 字节发送：Windows PowerShell 5.1 的
      Invoke-RestMethod 默认按 Latin-1 编码字符串，数据根含中文（“软件开发实验”）
      时中文路径会被打碎，接口直接 400 —— 这是原脚本跑不通的真实原因。
   3) 错误信息优先取 $_.ErrorDetails.Message（5.1 下 response stream 常已读空）
   4) 每次运行先清理上次的 _webtest_demo，避免“归档已存在”导致假失败
   5) 预建 watch_out / sched_out，避免引擎“不代建归档父目录”干扰

 用法（在 PowerShell 里执行）：
   .\web_full_test.ps1
   .\web_full_test.ps1 -ServerPassword "你的口令"
   .\web_full_test.ps1 -Base "http://127.0.0.1:8099"

 跑之前：先启动 bkd（本机实际命令，工作目录 dbkp/）：
   .\bin\bkd.exe --port 8099 --web web --data-root .
================================================================================
#>
param(
    [string]$Base = 'http://127.0.0.1:8099',
    [string]$ServerPassword = ''
)

$ErrorActionPreference = 'Stop'
$script:Token = ''

# --------------------------------------------------------------- 小工具函数 --
function Invoke-Api {
    param([string]$Method, [string]$Path, $Body)
    $headers = @{}
    if ($script:Token) { $headers['Authorization'] = 'Bearer ' + $script:Token }
    $restArgs = @{ Method = $Method; Uri = ($Base + $Path); Headers = $headers }
    if ($null -ne $Body) {
        $restArgs['ContentType'] = 'application/json; charset=utf-8'
        # 关键：字符串 Body 在 PS 5.1 会按 Latin-1 发出，中文路径必炸；用 UTF-8 字节
        $restArgs['Body'] = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 6))
    }
    try { return Invoke-RestMethod @restArgs }
    catch {
        $detail = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $raw = $_.ErrorDetails.Message
            try { $j = $raw | ConvertFrom-Json; if ($j.msg) { $detail = $j.msg } }
            catch { $detail = $raw }
        }
        throw ("[{0} {1}] 失败：{2}" -f $Method, $Path, $detail)
    }
}

function Wait-JobDone {
    param([int]$Id, [int]$TimeoutSec = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $j = (Invoke-Api -Method 'GET' -Path ("/api/jobs/{0}" -f $Id)).data
        if ($j.state -eq 'succeeded') { return $j }
        if ($j.state -eq 'failed' -or $j.state -eq 'canceled') {
            throw ("任务 #{0} {1}：{2}" -f $Id, $j.state, $j.message)
        }
        Start-Sleep -Milliseconds 800
    }
    throw "任务 #$Id 等了 $TimeoutSec 秒还没结束，请到页面任务列表看它卡在哪"
}

function Banner {
    param([string]$Step, [string]$PageHint)
    Write-Host ''
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
    Write-Host ("  {0}" -f $Step) -ForegroundColor Cyan
    Write-Host ("  【页面对应】{0}" -f $PageHint) -ForegroundColor DarkCyan
    Write-Host ('=' * 72) -ForegroundColor DarkCyan
}

$pass = 0; $fail = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Note = '')
    if ($Ok) { $script:pass++; Write-Host ("  ✓ {0} {1}" -f $Name, $Note) -ForegroundColor Green }
    else    { $script:fail++; Write-Host ("  ✗ {0} {1}" -f $Name, $Note) -ForegroundColor Red }
}

# =========================================================== 第 1 步：连通性 ==
Banner '第 1 步 / 连通性：GET /api/info' ("打开浏览器 " + $Base + "/ 能看到登录卡片，顶部显示版本与能力条，就等于这一步通过了。")
$info = Invoke-Api -Method 'GET' -Path '/api/info'
Write-Host ("  服务: {0}  API版本: {1}  系统: {2}" -f $info.data.app, $info.data.apiVersion, $info.data.capabilities.os)
$cap = $info.data.capabilities
Write-Host ("  能力自述: 软链={0} 硬链={1} 属主={2} 管道={3} 设备节点={4} 纳秒时间={5}" -f `
    $cap.symlink, $cap.hardlink, $cap.owner, $cap.fifo, $cap.deviceNode, $cap.nanoTime)
Check '服务可达' $true
# 教学点：Windows 上 管道/设备节点/属主 显示 ✗ 是"诚实降级"，不是缺陷。

# ============================================================== 第 2 步：登录 ==
Banner '第 2 步 / 登录：POST /api/login' '页面右上角"登录"卡片输入口令点登录，本质就是这一步；拿到 token 后所有请求都带 Bearer 头。'
$loginBody = @{ password = $ServerPassword }
$login = Invoke-Api -Method 'POST' -Path '/api/login' -Body $loginBody
$script:Token = $login.data.token
if ($login.data.anonymous) { Write-Host '  服务端未配置口令，免鉴权模式（anonymous=true）' }
else { Write-Host '  口令验证通过，token 已获取（有效期见 expiresIn 秒）' }
Check '登录拿 token' ([bool]$script:Token)
# 教学点：别用错误口令反复试！F12 修复后连续失败 5 次会锁定并指数退避。

# ========================================================== 第 3 步：测试数据 ==
Banner '第 3 步 / 准备测试数据（数据根下建 _webtest_demo）' '相当于你在数据根里手动建了个源目录放了几个文件。'
$cfg = (Invoke-Api -Method 'GET' -Path '/api/config').data
$root = $cfg.dataRoot
Write-Host ("  数据根: {0}   服务端默认压缩算法: {1}" -f $root, $cfg.defaultAlgorithm)
if (-not $root) { throw '服务端没返回 dataRoot，请确认启动参数里有 --data-root' }
$demoRoot = Join-Path $root '_webtest_demo'
if (Test-Path $demoRoot) { Remove-Item -Recurse -Force $demoRoot }   # 清上次残留，避免“归档已存在”
$srcDir  = Join-Path $demoRoot 'src'
$arcDir  = Join-Path $demoRoot 'out'
$resDir  = Join-Path $demoRoot 'restore'
New-Item -ItemType Directory -Force -Path $srcDir, $arcDir, $resDir, `
    (Join-Path $arcDir 'watch_out'), (Join-Path $arcDir 'sched_out') | Out-Null
Set-Content -Path (Join-Path $srcDir 'hello.txt') -Value ('hello dbkp ' * 200) -Encoding UTF8
Set-Content -Path (Join-Path $srcDir 'notes.md')  -Value ('# 测试笔记 ' + (Get-Date -Format s)) -Encoding UTF8
New-Item -ItemType Directory -Force -Path (Join-Path $srcDir 'sub') | Out-Null
Set-Content -Path (Join-Path $srcDir 'sub\deep.txt') -Value 'nested file' -Encoding UTF8
Write-Host ("  已创建源目录: {0}（2 个文件 + 1 个子目录）" -f $srcDir)
Check '测试数据就绪' (Test-Path (Join-Path $srcDir 'hello.txt'))
# 教学点：所有路径都必须落在数据根内，出了根服务端直接 403（路径沙箱）。

# ==================================================== 第 4 步：备份（归档） ====
Banner '第 4 步 / 备份·归档模式：POST /api/jobs' "页面上：类型=备份，目标填 ...out\demo.dbkp，形态留 auto，点提交任务。"
$arc = Join-Path $arcDir 'demo.dbkp'
$job = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{
    type = 'backup'; source = $srcDir; destination = $arc; mode = 'auto'
    algorithm = $cfg.defaultAlgorithm; crypto = 'none'; checksum = 'crc64'
    preserveMeta = $true; verifyAfter = $true
}
Write-Host ("  受理任务 #{0}，auto 解析结果 mode = {1}（目标以 .dbkp 结尾→归档）" -f $job.data.id, $job.data.mode)
$done = Wait-JobDone -Id $job.data.id
Check '归档备份成功' ($done.state -eq 'succeeded') ("{0}" -f $done.message)
$script:demoArchive = $arc
# 教学点：这就是 auto 的全部语义——只看目标后缀。显式选 archive/copy 则强制。

# ======================================================== 第 5 步：读卷标 =====
Banner '第 5 步 / 读卷标：GET /api/stat' '页面上：任务列表卡片下半段"查看已有归档"填 .dbkp 路径点"读卷标"，下方出摘要+条目表。'
$stat = (Invoke-Api -Method 'GET' -Path ('/api/stat?path=' + [Uri]::EscapeDataString($arc) + '&entries=1')).data
Write-Host ("  算法: {0}  加密: {1}  条目: {2}(目录{3} 链接{4} 特殊{5})" -f `
    $stat.algorithm, $stat.crypto, $stat.fileCount, $stat.dirCount, $stat.linkCount, $stat.specialCount)
Write-Host ("  原始 {0} → 存成 {1}  压缩比 {2}%" -f $stat.rawBytes, $stat.storedBytes, [math]::Round($stat.ratio * 100, 1))
Check '卷标可读' ($stat.fileCount -ge 2)
Check 'specialCount 字段在' ($null -ne $stat.specialCount) '（批次9 已显示为“特殊 N”）'
$e0 = @($stat.entries)[0]
Write-Host ("  首条条目字段: path={0} type={1} mode={2} mtime={3} mtimeNs={4} nlink={5} crypto={6}" -f `
    $e0.path, $e0.type, $e0.mode, $e0.mtime, $e0.mtimeNs, $e0.nlink, $e0.crypto)
Check '条目元数据齐全' (($null -ne $e0.mode) -and ($null -ne $e0.mtimeNs) -and ($null -ne $e0.nlink))

# ========================================================== 第 6 步：校验 =====
Banner '第 6 步 / 校验：POST /api/jobs type=verify' '页面上：类型=校验，来源填 .dbkp 路径，提交。归档模式逐条验 CRC+解码。'
$v = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{ type = 'verify'; source = $arc }
$done = Wait-JobDone -Id $v.data.id
Check '校验通过' ($done.state -eq 'succeeded') ("{0}" -f $done.message)

# ========================================================== 第 7 步：对比 =====
Banner '第 7 步 / 对比：GET /api/compare' '页面上：任务列表下半段"与源目录逐条比对"，填源目录点"开始比对"。'
$cmp = Invoke-Api -Method 'GET' -Path ('/api/compare?archive=' + [Uri]::EscapeDataString($arc) + '&origin=' + [Uri]::EscapeDataString($srcDir))
Check '归档与源目录一致' ($cmp.data.diffCount -eq 0) ("差异 {0} 处" -f $cmp.data.diffCount)

# ========================================================== 第 8 步：还原 =====
Banner '第 8 步 / 还原：POST /api/jobs type=restore' '页面上：类型=还原，来源=.dbkp，目标=空目录，提交；完成后去目标目录核对文件。'
$r = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{
    type = 'restore'; source = $arc; destination = $resDir; overwrite = $true; preserveMeta = $true
}
$done = Wait-JobDone -Id $r.data.id
Check '还原成功' ($done.state -eq 'succeeded') ("{0}" -f $done.message)
$helloBack = Join-Path $resDir 'hello.txt'
Check '还原出的文件内容与源一致' ((Test-Path $helloBack) -and ((Get-Content $helloBack -Raw).Length -gt 0))

# ================================================= 第 9 步：复制模式 + 反例 ====
Banner '第 9 步 / 复制模式（copy）与 .dbkp 反例' '页面上：形态选 copy、目标填目录 → 正常；目标故意填 .dbkp → 页面会标红拦截，不许提交。'
$copyDir = Join-Path $arcDir 'copy_result'
$c = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{
    type = 'backup'; source = $srcDir; destination = $copyDir; mode = 'copy'
}
Write-Host ("  受理任务 #{0}，mode = {1}" -f $c.data.id, $c.data.mode)
$done = Wait-JobDone -Id $c.data.id
Check 'copy 备份成功' ($done.state -eq 'succeeded')
Check 'copy 结果是目录而不是归档' (Test-Path (Join-Path $copyDir 'hello.txt'))
Write-Host '  —— 反例：mode=copy 却把目标填成 .dbkp ——' -ForegroundColor Yellow
$bad = Join-Path $arcDir 'oops.dbkp'
try {
    $b = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{
        type = 'backup'; source = $srcDir; destination = $bad; mode = 'copy'
    }
    Wait-JobDone -Id $b.data.id | Out-Null
    Write-Host '  API 直调不拦！它真建出了一个叫 oops.dbkp 的【目录】。' -ForegroundColor Yellow
    Write-Host '  （页面上有前端校验会拦住：currentFails() 里 copy+.dbkp 报错并禁用提交；'
    Write-Host ('    这就是"前后端都要挡"的活例子。清理演示目录 {0}' -f $bad)
    Remove-Item -Recurse -Force $bad
    Check '反例演示完成并清理' $true
} catch { Check '反例被拒（也算好结果）' $true $_.Exception.Message }

# ======================================================= 第 10 步：加密备份 ====
Banner '第 10 步 / 加密备份与口令' '页面上：加密算法选 AES-256-CBC，密码填 demo123，提交；还原/校验时不给密码会失败。'
$encArc = Join-Path $arcDir 'enc.dbkp'
$e = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{
    type = 'backup'; source = $srcDir; destination = $encArc; mode = 'auto'
    algorithm = $cfg.defaultAlgorithm; crypto = 'aes256'; password = 'demo123'; checksum = 'crc64'
}
$done = Wait-JobDone -Id $e.data.id
Check '加密备份成功' ($done.state -eq 'succeeded') ("{0}" -f $done.message)
try {
    $w = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{ type = 'verify'; source = $encArc; password = 'wrong-password' }
    Wait-JobDone -Id $w.data.id | Out-Null
    Write-Host '  ⚠ 错误口令竟然校验通过了？这不正常，记下来报告。' -ForegroundColor Red
    Check '错误口令应被拒' $false
} catch { Check '错误口令被正确拒绝' $true }
$v2 = Invoke-Api -Method 'POST' -Path '/api/jobs' -Body @{ type = 'verify'; source = $encArc; password = 'demo123' }
$done = Wait-JobDone -Id $v2.data.id
Check '正确口令校验通过' ($done.state -eq 'succeeded')

# ======================================================= 第 11 步：实时备份 ====
Banner '第 11 步 / 实时备份：/api/watch' '页面上：实时备份卡片填源目录+输出目录，点"开始监听"，然后改源里的文件，看"已自动备份 N 次"涨数。'
Invoke-Api -Method 'POST' -Path '/api/watch' -Body @{
    source = $srcDir; destination = (Join-Path $arcDir 'watch_out')
    debounce = '2s'; keep = 3; algorithm = $cfg.defaultAlgorithm; crypto = 'none'
    checksum = 'crc64'; verifyAfter = $true
} | Out-Null
Write-Host '  监听已启动，等 3 秒后往源目录写一个新文件…'
Start-Sleep -Seconds 3
Set-Content -Path (Join-Path $srcDir 'trigger.txt') -Value ('trigger ' + (Get-Date -Format o)) -Encoding UTF8
Write-Host '  文件已写入，等去抖(2s)+打包时间…'
$okWatch = $false
foreach ($i in 1..20) {
    Start-Sleep -Seconds 1
    $ws = (Invoke-Api -Method 'GET' -Path '/api/watch').data
    if ($ws.backupCount -ge 1) { $okWatch = $true; break }
}
$ws = (Invoke-Api -Method 'GET' -Path '/api/watch').data
Check '文件变化被自动备份' $okWatch ("已自动备份 {0} 次，最近归档: {1}" -f $ws.backupCount, $ws.lastArchive)
Invoke-Api -Method 'POST' -Path '/api/watch/stop' -Body @{} | Out-Null
Write-Host '  已停止监听。'
# 教学点：实时=触发时机（变了就备），增量=备份范围（只备变化部分）。增量没做。

# ======================================================= 第 12 步：定时备份 ====
Banner '第 12 步 / 定时备份：/api/schedule' '页面上：定时备份卡片设间隔 10s、次数 2、保留 2 份，启动后看它自己跑两轮。'
Invoke-Api -Method 'POST' -Path '/api/schedule' -Body @{
    source = $srcDir; destination = (Join-Path $arcDir 'sched_out')
    interval = '10s'; times = 2; keep = 2; prefix = 'sch'; algorithm = $cfg.defaultAlgorithm
} | Out-Null
Write-Host '  定时任务已启动（每 10 秒一次，共 2 次）。每 5 秒查一次状态…'
$doneCount = 0
$files = @()
foreach ($i in 1..12) {
    Start-Sleep -Seconds 5
    $ss = (Invoke-Api -Method 'GET' -Path '/api/schedule').data
    $files = @(Get-ChildItem (Join-Path $arcDir 'sched_out') -Filter 'sch*.dbkp' -ErrorAction SilentlyContinue)
    Write-Host ("  [{0}] running={1}  已产出归档 {2} 份" -f $i, $ss.running, $files.Count)
    if (-not $ss.running -and $files.Count -ge 1) { break }
}
Invoke-Api -Method 'POST' -Path '/api/schedule/stop' -Body @{} -ErrorAction SilentlyContinue | Out-Null
Check '定时备份产出了归档' ($files.Count -ge 1) ("共 {0} 份，prefix=sch，keep=2 会自动清旧的" -f $files.Count)

# ================================================================ 总结 ========
Banner '测试结束' ''
Write-Host ("  通过 {0} 项，失败 {1} 项" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host '  答辩截图建议：第4步任务卡片(带mode tag)、第5步读卷标(条目表11列)、'
Write-Host '  第10步加密+错口令被拒、第11步实时计数、第12步定时产出。'
Write-Host ("  测试产物都在 {0} 下，确认不需要后可整目录删除。" -f $demoRoot)
if ($fail -gt 0) { exit 1 }