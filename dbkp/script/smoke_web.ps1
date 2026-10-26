# ============================================================================
#  smoke_web.ps1 -- bkd（Web 服务端）端到端冒烟测试
#
#  覆盖：静态页 / 登录鉴权 / 建备份任务 / 轮询进度 / 读归档卷标 / 还原 /
#        校验 / 取消 / 错误处理 / 路径越界防护 / SSE 进度流 / 关服。
#  用法：  powershell -File script/smoke_web.ps1     （退出码 0 = 全部通过）
# ============================================================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # 否则 Invoke-WebRequest 的进度条会刷屏
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$sandbox = Join-Path $root 'tmp/webtest'
$port    = 18081
$base    = "http://127.0.0.1:$port"
$pass    = 'test123'
$script:fail = 0
$token   = ''

function Check($name, $cond, $detail) {
    if ($cond) { Write-Host "  [OK]   $name" -ForegroundColor DarkGreen }
    else { $script:fail++; Write-Host "  [FAIL] $name  $detail" -ForegroundColor Red }
}

# 统一调用 API：返回 @{status;json;text}。非 2xx 也读出响应体（断言要看 msg）。
function Api($method, $path, $bodyObj) {
    $headers = @{}
    if ($token -ne '') { $headers['Authorization'] = "Bearer $token" }
    $params = @{ Uri = "$base$path"; Method = $method; Headers = $headers
                 UseBasicParsing = $true; TimeoutSec = 30 }
    if ($null -ne $bodyObj) {
        $json = $bodyObj | ConvertTo-Json -Depth 6 -Compress
        $params['ContentType'] = 'application/json; charset=utf-8'
        $params['Body'] = [System.Text.Encoding]::UTF8.GetBytes($json)
    }
    $status = 0; $text = ''
    try {
        $resp = Invoke-WebRequest @params
        $status = [int]$resp.StatusCode; $text = $resp.Content
    } catch {
        $r = $_.Exception.Response
        if ($null -eq $r) { throw }
        $status = [int]$r.StatusCode
        $reader = New-Object System.IO.StreamReader($r.GetResponseStream())
        $text = $reader.ReadToEnd()
    }
    $obj = $null
    if ($text -and $text.TrimStart().StartsWith('{')) { try { $obj = $text | ConvertFrom-Json } catch { $obj = $null } }
    return @{ status = $status; json = $obj; text = $text }
}

Write-Host '== 准备测试数据 ==' -ForegroundColor Cyan
if (Test-Path $sandbox) { Remove-Item -Recurse -Force $sandbox }
New-Item -ItemType Directory -Force -Path (Join-Path $sandbox 'src/sub') | Out-Null
Set-Content -Path (Join-Path $sandbox 'src/a.txt') -Value ('alpha ' * 200) -Encoding ascii
Set-Content -Path (Join-Path $sandbox 'src/sub/b.txt') -Value 'beta payload' -Encoding ascii
# 中文文件名：验证 UTF-8 路径在内核侧（而不是 HTTP 侧）也能走通
[System.IO.File]::WriteAllText((Join-Path $sandbox 'src/中文说明.txt'), 'UTF-8 name content', (New-Object System.Text.UTF8Encoding($false)))
New-Item -ItemType Directory -Force -Path (Join-Path $sandbox 'out') | Out-Null

Write-Host '== 启动 bkd ==' -ForegroundColor Cyan
$exe = Join-Path $root 'bin/bkd.exe'
if (-not (Test-Path $exe)) { Write-Host '先执行 mingw32-make 生成 bin/bkd.exe' -ForegroundColor Red; exit 2 }
$proc = Start-Process -FilePath $exe -ArgumentList @(
    '--port', "$port", '--web', 'web', '--data-root', $sandbox,
    '--password', $pass, '--log-level', 'info') -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $root 'tmp/bkd-smoke.log') `
    -RedirectStandardOutput (Join-Path $root 'tmp/bkd-smoke.out')
Start-Sleep -Milliseconds 1500

try {
    Write-Host '== 静态页与服务信息 ==' -ForegroundColor Cyan
    $r = Api GET '/' $null
    Check 'GET / 返回页面' ($r.status -eq 200 -and $r.text -match 'dbkp') $r.text.Substring(0, [Math]::Min(120, $r.text.Length))
    $r = Api GET '/api/info' $null
    Check 'GET /api/info 免鉴权可用' ($r.status -eq 200 -and $r.json.code -eq 0) $r.text
    Check 'info 带平台能力' ($null -ne $r.json.data.capabilities.os) ''
    $r = Api GET '/api/config' $null
    Check '未登录访问 /api/config 被拒 401' ($r.status -eq 401) "实际 $($r.status) $($r.text)"

    Write-Host '== 登录 ==' -ForegroundColor Cyan
    $r = Api POST '/api/login' @{ password = 'wrong-pass' }
    Check '错误口令返回 401' ($r.status -eq 401) $r.text
    $r = Api POST '/api/login' @{ password = $pass }
    Check '正确口令返回 token' ($r.status -eq 200 -and $r.json.data.token) $r.text
    $token = $r.json.data.token
    $r = Api GET '/api/config' $null
    Check '带 token 可访问 /api/config' ($r.status -eq 200 -and $r.json.data.algorithms.Count -ge 4) "实际 $($r.status)"
    Check '算法列表含 huffman' ($r.json.data.algorithms -contains 'huffman') ($r.json.data.algorithms -join ',')

    Write-Host '== 备份任务（归档 + 压缩） ==' -ForegroundColor Cyan
    $archive = ((Join-Path $sandbox 'out/backup.dbkp') -replace '\\', '/')
    $src     = ((Join-Path $sandbox 'src') -replace '\\', '/')
    $r = Api POST '/api/jobs' @{ type = 'backup'; source = $src; destination = $archive;
                                 algorithm = 'huffman'; crypto = 'none'; checksum = 'crc64';
                                 label = 'smoke-backup';
                                 filter = @{ excludePaths = @('*.tmp') } }
    Check 'POST /api/jobs 受理并返回 201' ($r.status -eq 201 -and $r.json.data.id) $r.text
    Check '自动判定 mode=archive' ($r.json.data.mode -eq 'archive') $r.text
    $jobId = $r.json.data.id

    $state = ''; $log = ''
    for ($i = 0; $i -lt 60; $i++) {
        $r = Api GET "/api/jobs/$jobId`?log=1" $null
        $state = $r.json.data.state
        $log = ($r.json.data.log -join ' | ')
        if ($state -in @('succeeded', 'failed', 'canceled')) { break }
        Start-Sleep -Milliseconds 200
    }
    Check "任务最终成功（state=$state）" ($state -eq 'succeeded') $log
    Check '进度汇报过条目' ($r.json.data.entriesDone -ge 3) "entries=$($r.json.data.entriesDone)"
    Check '任务日志非空' ($log.Length -gt 0) $log
    Check '归档文件已生成' (Test-Path $archive) ''

    Write-Host '== 读归档卷标 ==' -ForegroundColor Cyan
    $r = Api GET "/api/stat?path=$([uri]::EscapeDataString($archive))" $null
    Check 'GET /api/stat 返回卷标' ($r.status -eq 200 -and $r.json.data.fileCount -ge 3) $r.text
    Check '卷标里的算法是 huffman' ($r.json.data.algorithm -eq 'huffman') $r.json.data.algorithm

    Write-Host '== 还原 + 校验 ==' -ForegroundColor Cyan
    $target = ((Join-Path $sandbox 'restore') -replace '\\', '/')
    $r = Api POST '/api/jobs' @{ type = 'restore'; source = $archive; destination = $target; overwrite = $true }
    $rid = $r.json.data.id
    Check '还原任务已受理' ($r.status -eq 201 -and $rid) $r.text
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $rr = Api GET "/api/jobs/$rid" $null
        $state = $rr.json.data.state
        if ($state -in @('succeeded', 'failed', 'canceled')) { break }
        Start-Sleep -Milliseconds 200
    }
    Check "还原成功（state=$state）" ($state -eq 'succeeded') $rr.json.data.message
    Check '还原后中文文件名存在' (Test-Path (Join-Path $sandbox 'restore/中文说明.txt')) ''
    Check '还原后普通文件存在' (Test-Path (Join-Path $sandbox 'restore/a.txt')) ''

    $r = Api POST '/api/jobs' @{ type = 'verify'; source = $archive }
    $vid = $r.json.data.id
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $rv = Api GET "/api/jobs/$vid" $null
        $state = $rv.json.data.state
        if ($state -in @('succeeded', 'failed', 'canceled')) { break }
        Start-Sleep -Milliseconds 200
    }
    Check "归档校验通过（state=$state）" ($state -eq 'succeeded') $rv.json.data.message

    Write-Host '== 取消与错误处理 ==' -ForegroundColor Cyan
    $slow = ((Join-Path $sandbox 'out/slow.dbkp') -replace '\\', '/')
    $r = Api POST '/api/jobs' @{ type = 'backup'; source = $src; destination = $slow; algorithm = 'lzhuff' }
    $cid = $r.json.data.id
    $rc = Api POST "/api/jobs/$cid/cancel" $null
    Check '取消请求返回 200（已受理）或 409（已抢先跑完）' ($rc.status -eq 200 -or $rc.status -eq 409) "实际 $($rc.status) $($rc.text)"
    $state = ''
    for ($i = 0; $i -lt 80; $i++) {
        $fin = Api GET "/api/jobs/$cid" $null
        $state = $fin.json.data.state
        if ($state -in @('succeeded', 'failed', 'canceled')) { break }
        Start-Sleep -Milliseconds 150
    }
    Check "终态合法（$state）" ($state -in @('succeeded', 'canceled')) $fin.json.data.message
    Check '取消过的任务不会假装成功' (-not ($rc.status -eq 200 -and $state -ne 'canceled')) "cancel=200 但 state=$state"
    $r = Api POST "/api/jobs/$cid/cancel" $null
    Check '已结束的任务不能再取消 -> 409' ($r.status -eq 409) "实际 $($r.status)"

    $r = Api POST '/api/jobs' @{ type = 'backup'; source = '/definitely/not/here'; destination = $archive }
    Check '不存在的来源当场报错' ($r.status -eq 400) "实际 $($r.status) $($r.text)"
    $r = Api POST '/api/jobs' $null
    Check '空请求体返回 400' ($r.status -eq 400) "实际 $($r.status)"
    $r = Api GET '/api/nope' $null
    Check '未知接口返回 JSON 404' ($r.status -eq 404 -and $r.json.code -ne 0) $r.text
    $r = Api DELETE '/api/jobs' $null
    Check '不支持的方法返回 405' ($r.status -eq 405) "实际 $($r.status)"

    Write-Host '== 越界防护 ==' -ForegroundColor Cyan
    $outside = ((Join-Path $root 'src') -replace '\\', '/')
    $r = Api POST '/api/jobs' @{ type = 'backup'; source = $outside; destination = $archive }
    Check 'dataRoot 之外的 source 被拒' ($r.status -eq 400) "实际 $($r.status) $($r.text)"
    $r = Api GET '/api/browse?path=../../../Windows' $null
    Check 'browse 目录穿越被拦' ($r.status -eq 403 -or $r.status -eq 404) "实际 $($r.status)"
    $r = Api GET '/%2e%2e/%2e%2e/Makefile' $null
    Check '静态文件穿越被拦' ($r.status -eq 403 -or $r.status -eq 404) "实际 $($r.status)"

    Write-Host '== SSE 进度流 ==' -ForegroundColor Cyan
    $r = Api GET "/api/events?job=$jobId" $null
    $head = $r.text.Substring(0, [Math]::Min(200, $r.text.Length))
    Check 'SSE 输出 event-stream' ($r.status -eq 200 -and $r.text -match 'event: hello') $head
    Check 'SSE 推送 done 收尾' ($r.text -match 'event: done') ''
    Check 'SSE 事件里带进度 JSON' ($r.text -match '"state"') ''

    Write-Host '== 任务列表 ==' -ForegroundColor Cyan
    $r = Api GET '/api/jobs?limit=10' $null
    Check 'GET /api/jobs 返回列表' ($r.status -eq 200 -and $r.json.data.jobs.Count -ge 4) $r.text
    Check '列表按新->旧排列' ($r.json.data.jobs[0].id -gt $r.json.data.jobs[1].id) ''
} finally {
    Write-Host '== 关闭服务 ==' -ForegroundColor Cyan
    $r = $null
    try { $r = Api POST '/api/shutdown' $null } catch { }
    # 这条断言盯的是"先回响应再停服务"：handler 里直接 server->stop() 会把
    # 本连接一起 shutdown 掉，客户端只看到连接被掐（没有 200，也没有 body）。
    Check 'POST /api/shutdown 返回 200' ($r.status -eq 200) "实际 $($r.status) $($r.text)"
    Start-Sleep -Milliseconds 1200
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Check 'bkd 进程已退出' $proc.HasExited ''
}

if ($script:fail -eq 0) { Write-Host "`nWEB SMOKE OK" -ForegroundColor Green; exit 0 }
Write-Host "`nWEB SMOKE FAILED: $script:fail 项" -ForegroundColor Red
exit 1

