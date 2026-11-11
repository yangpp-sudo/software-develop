# verify_web_watch.ps1 -- 端到端验证 Web /api/watch 实时备份接口
# 流程：起 bkd -> POST /api/watch -> 改源文件 -> 轮询 backupCount>0 -> GET /api/stat 验证归档 -> stop
$ErrorActionPreference = 'SilentlyContinue'
Set-Location "$PSScriptRoot\..\dbkp"

$port = 8097
$bkd  = ".\bin\bkd.exe"
$tmp  = "tmp\webwatch"
$src  = "$tmp\src"
$dst  = "$tmp\out"

if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $src, $dst | Out-Null
"init" | Set-Content "$src\a.txt"

$pass = 0; $fail = 0
function Check($label, $cond) {
    if ($cond) { Write-Host "  [OK] $label" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  [FAIL] $label" -ForegroundColor Red; $script:fail++ }
}
$base = "http://127.0.0.1:$port"

# 起服务
Get-Process bkd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500
Start-Process -FilePath $bkd -ArgumentList "--port","$port","--web","web" -WindowStyle Hidden
Start-Sleep -Seconds 1

# POST JSON：PowerShell 5.1 默认会把非 ASCII 正文转成 '?'，必须手动编成 UTF-8 字节
function PostJson($url, $obj, $headers) {
    $json = ($obj | ConvertTo-Json)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Invoke-RestMethod -Uri $url -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers $headers
}

# 登录拿 token（免口令模式）
$login = PostJson "$base/api/login" @{ password = "" } @{}
$tok = $login.data.token
$H = @{ Authorization = "Bearer $tok" }
Check "login ok" ([bool]$tok)

# POST /api/watch 启动监听（用绝对路径，避开相对解析歧义）
$srcAbs = (Resolve-Path $src).Path
$dstAbs = (Resolve-Path $dst).Path
$st = PostJson "$base/api/watch" @{ source = $srcAbs; destination = $dstAbs; debounce = "1s"; keep = 0; crypto = "none"; checksum = "crc64" } $H
Check "watch running=true" ($st.data.running -eq $true)

# GET /api/watch 状态
$s0 = Invoke-RestMethod -Uri "$base/api/watch" -Method Get -Headers $H
Check "status native flag present" ($null -ne $s0.data.native)

# 改动源文件，等待 debounce + 备份
"changed $(Get-Random)" | Set-Content "$src\b.txt"
Start-Sleep -Seconds 5
$s1 = Invoke-RestMethod -Uri "$base/api/watch" -Method Get -Headers $H
Check "backupCount >= 1" ($s1.data.backupCount -ge 1)

# 归档文件应落盘并可 verify
$dbkp = @(Get-ChildItem "$dst\*.dbkp" -ErrorAction SilentlyContinue)
Check "archive file on disk" ($dbkp.Count -ge 1)
if ($dbkp.Count -ge 1) {
    $last = $dbkp[-1].FullName
    $stat = Invoke-RestMethod -Uri "$base/api/stat?path=$([uri]::EscapeDataString($last))" -Headers $H
    Check "api/stat reads archive" ($stat.code -eq 0)
}

# POST /api/watch/stop 停止
$sp = PostJson "$base/api/watch/stop" @{} $H
Start-Sleep -Seconds 2
$s2 = Invoke-RestMethod -Uri "$base/api/watch" -Method Get -Headers $H
Check "watch stopped running=false" ($s2.data.running -eq $false)

# 清理：关服务
Get-Process bkd -ErrorAction SilentlyContinue | Stop-Process -Force

Write-Host "`n============================" -ForegroundColor Cyan
Write-Host "  PASS=$pass  FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Red"})
Write-Host "============================" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
