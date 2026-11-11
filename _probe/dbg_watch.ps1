# dbg_watch.ps1 -- 干净地抓取 /api/watch 的真实响应，结果写文件避免控制台污染
$ErrorActionPreference = 'SilentlyContinue'
Set-Location "$PSScriptRoot\..\dbkp"
$log = "tmp\dbg_watch.txt"
"START" | Set-Content $log

$port = 8123
$base = "http://127.0.0.1:$port"
Get-Process bkd -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Remove-Item -Recurse -Force tmp\dbgsrc -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "tmp\dbgsrc\src","tmp\dbgsrc\out" | Out-Null
"x" | Set-Content "tmp\dbgsrc\src\a.txt"

Start-Process -FilePath ".\bin\bkd.exe" -ArgumentList "--port","$port","--web","web" -WindowStyle Hidden
# 等待服务就绪
$ready = $false
for ($k=0; $k -lt 20; $k++) {
    try { Invoke-RestMethod -Uri "$base/api/info" -TimeoutSec 2 | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 300 }
}
"READY=$ready" | Add-Content $log

function PostUtf8($url, $obj, $headers) {
    $json = ($obj | ConvertTo-Json -Compress)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    Invoke-RestMethod -Uri $url -Method Post -Body $bytes -ContentType 'application/json; charset=utf-8' -Headers $headers
}
try { $login = PostUtf8 "$base/api/login" @{password=""} @{} } catch { "LOGIN ERR: $($_.ErrorDetails.Message)" | Add-Content $log }
$H = @{ Authorization = "Bearer $($login.data.token)" }
$srcAbs = (Resolve-Path "tmp\dbgsrc\src").Path
$dstAbs = (Resolve-Path "tmp\dbgsrc\out").Path
"SRC=$srcAbs" | Add-Content $log
"SRC-BYTES-HEX=$( ($([System.Text.Encoding]::UTF8.GetBytes($srcAbs)) | ForEach-Object { $_.ToString('x2') }) -join '')" | Add-Content $log
try {
    $r = PostUtf8 "$base/api/watch" @{source=$srcAbs;destination=$dstAbs;debounce="1s";crypto="none"} $H
    "WATCH RESP running=$($r.data.running) code=$($r.code) msg=$($r.msg)" | Add-Content $log
} catch {
    "WATCH HTTP ERR: $($_.Exception.Message)" | Add-Content $log
    "WATCH BODY: $($_.ErrorDetails.Message)" | Add-Content $log
}
Get-Process bkd -ErrorAction SilentlyContinue | Stop-Process -Force
"DONE" | Add-Content $log
