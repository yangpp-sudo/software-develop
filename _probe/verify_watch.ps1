# verify_watch.ps1 -- 端到端验证 bk watch（实时备份）
# 场景：启动 watch → 改文件 → 等 debounce → 断言归档出现 → 修改 → 再断言第二份归档
$ErrorActionPreference = 'SilentlyContinue'
Set-Location "$PSScriptRoot\..\dbkp"

$bk = "bin\bk.exe"
$tmp = "tmp\watch_e2e"
$src = "$tmp\src"
$dst = "$tmp\out"

# --- 清理 ---
if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
New-Item -ItemType Directory -Force -Path $src | Out-Null
New-Item -ItemType Directory -Force -Path $dst | Out-Null

# 初始文件
"hello watch" | Set-Content "$src\init.txt"

$pass = 0
$fail = 0
function Check($label, $cond) {
    if ($cond) { Write-Host "  [OK] $label" -ForegroundColor Green; $script:pass++ }
    else       { Write-Host "  [FAIL] $label" -ForegroundColor Red;   $script:fail++ }
}

# --- 1. 启动 bk watch (后台进程) ---
Write-Host "`n=== Step 1: start bk watch ===" -ForegroundColor Cyan
$watchProc = Start-Process -FilePath ".\$bk" `
    -ArgumentList @("watch", $src, $dst, "--debounce", "1s", "--keep", "0") `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput "$tmp\watch.log" `
    -RedirectStandardError "$tmp\watch.err"
Start-Sleep -Seconds 2
Check "watch process running" (-not $watchProc.HasExited)

# 确认初始化日志
Start-Sleep -Milliseconds 500
$logContent = if (Test-Path "$tmp\watch.log") { Get-Content "$tmp\watch.log" -Raw } else { "" }
Check "watch banner present" ($logContent -match "watch started")

# --- 2. 新增文件触发第一次备份 ---
Write-Host "`n=== Step 2: add new file ===" -ForegroundColor Cyan
"new content" | Set-Content "$src\added.txt"
# 等 debounce(1s) + 备份时间(约1s) + margin
Start-Sleep -Seconds 4
$archives = @(Get-ChildItem "$dst\*.dbkp" -ErrorAction SilentlyContinue)
Check "at least 1 archive after add" ($archives.Count -ge 1)

# --- 3. 修改文件触发第二次备份 ---
Write-Host "`n=== Step 3: modify file ===" -ForegroundColor Cyan
$before = @(Get-ChildItem "$dst\*.dbkp").Count
Start-Sleep -Seconds 1  # 确保时间戳变化
"modified content" | Set-Content "$src\added.txt"
Start-Sleep -Seconds 4
$after = @(Get-ChildItem "$dst\*.dbkp").Count
Check "archive count increased" ($after -gt $before)

# --- 4. 验证归档可读 ---
Write-Host "`n=== Step 4: verify archive ===" -ForegroundColor Cyan
$latest = (Get-ChildItem "$dst\*.dbkp" | Sort-Object LastWriteTime -Descending)[0]
$vi = & $bk verify $latest.FullName 2>&1
Check "bk verify ok" ($LASTEXITCODE -eq 0)

# --- 5. 停止 watch ---
Write-Host "`n=== Step 5: stop watch ===" -ForegroundColor Cyan
Stop-Process -Id $watchProc.Id -Force -ErrorAction SilentlyContinue
$watchProc.WaitForExit(5000) | Out-Null
Check "watch exited" $watchProc.HasExited

# --- 汇总 ---
Write-Host "`n============================" -ForegroundColor Cyan
Write-Host "  PASS=$pass  FAIL=$fail" -ForegroundColor $(if ($fail -eq 0) {"Green"} else {"Red"})
Write-Host "============================" -ForegroundColor Cyan
if ($fail -gt 0) { exit 1 }
