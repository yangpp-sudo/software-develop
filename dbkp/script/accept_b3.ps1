# ============================================================================
#  accept_b3.ps1 -- 第三批（F4/F6b/F9/F11）验收脚本
#  覆盖清单验收标准：
#    A) 并发：两个 bk backup 同时写同一目标 -> 恰好一个成功，另一个报占用/已存在
#    B) kill：备份中途杀进程 -> 旧箱字节完好、只有 .tmp 残骸；
#       verify 报"上次备份未完成"；不带 --force 重跑被拒；带 --force 恢复
#    C) 空壳：recordCount>0 而 payloadSize==0 的箱子 -> bk verify 非零退出
#    D) 同秒双写：schedule 连续落笔 -> 归档名互不相同（毫秒字段/碰撞后缀）
#    E) F9：归档放在源目录内，同 dest 双跑（第 2 次 --force）-> 新箱不含旧箱记录
#  说明：用 .NET Process 直起 bk.exe，ExitCode/stdout/stderr 全部可靠取回，
#  绕开 PowerShell 5.1 的 Start-Process ExitCode 为空与 2>&1 NativeCommandError 两个坑。
#  usage: powershell -ExecutionPolicy Bypass -File script/accept_b3.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$BK   = Join-Path $root "bin\bk.exe"
if (!(Test-Path $BK)) { Write-Host "build first: $BK not found"; exit 1 }

$work = Join-Path $env:TEMP ("dbkp_accept_b3_" + $PID)
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null

$script:pass = 0
$script:fail = 0
function Check($name, $cond, $detail) {
    if ($cond) { Write-Host ("  PASS  " + $name); $script:pass++ }
    else { Write-Host ("  FAIL  " + $name + "  [" + $detail + "]"); $script:fail++ }
}
function OneLine($s) { ([string]$s) -replace "`r?`n", " | " }

function Start-BK([string[]]$cmdArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $BK
    $psi.Arguments = ($cmdArgs | ForEach-Object {
        if ($_ -match '[ "]') { '"' + $_ + '"' } else { $_ }
    }) -join ' '
    $psi.WorkingDirectory = $work
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [System.Diagnostics.Process]::Start($psi)
}
function Run-BK([string[]]$cmdArgs) {
    $p = Start-BK $cmdArgs
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(240000)) { throw ("bk timed out: " + ($cmdArgs -join ' ')) }
    @{ rc = $p.ExitCode; out = $o.Result; err = $e.Result }
}

function New-Src($p, [int]$mb = 0) {
    $full = Join-Path $work $p
    if (Test-Path $full) { Remove-Item -Recurse -Force $full }
    New-Item -ItemType Directory -Force -Path (Join-Path $full "sub") | Out-Null
    [IO.File]::WriteAllText((Join-Path $full "a.txt"), ("hello dbkp " * 500))
    [IO.File]::WriteAllText((Join-Path $full "sub\b.txt"), "deep content")
    if ($mb -gt 0) {
        # 随机数据不可压缩，保证备份持续数秒，便于并发/kill 窗口命中
        $abs = Join-Path $full "big.bin"
        $buf = New-Object byte[] (1MB)
        (New-Object Random).NextBytes($buf)
        $fs = [IO.File]::Create($abs)
        for ($i = 0; $i -lt $mb; $i++) { $fs.Write($buf, 0, $buf.Length) }
        $fs.Close()
    }
}

Write-Host ("run start: " + (Get-Date) + "  workdir: " + $work)

# ---------------------------------------------------------------- A) 并发
Write-Host "=== A: concurrent double backup (same target) ==="
New-Src "asrc" 64
$boxA = Join-Path $work "abox.dbkp"
$p1 = Start-BK @("backup", "asrc", $boxA)
$o1 = $p1.StandardOutput.ReadToEndAsync(); $e1 = $p1.StandardError.ReadToEndAsync()
$p2 = Start-BK @("backup", "asrc", $boxA)
$o2 = $p2.StandardOutput.ReadToEndAsync(); $e2 = $p2.StandardError.ReadToEndAsync()
$w1 = $p1.WaitForExit(240000); $w2 = $p2.WaitForExit(240000)
if (-not $w1 -or -not $w2) { Write-Host "  FATAL: backup processes timed out"; exit 1 }
$rcA = $p1.ExitCode; $rcB = $p2.ExitCode
Write-Host ("  rc1=" + $rcA + "  rc2=" + $rcB)
$okCount  = @(@($rcA, $rcB) | Where-Object { $_ -eq 0 }).Count
$badCount = @(@($rcA, $rcB) | Where-Object { $_ -ne 0 }).Count
Check "A1 exactly one backup succeeded" ($okCount -eq 1 -and $badCount -eq 1) ("rc1=$rcA rc2=$rcB")
$errLose = if ($rcA -ne 0) { $e1.Result } else { $e2.Result }
Write-Host ("  loser stderr: " + (OneLine $errLose))
Check "A2 loser reports locked/exists/incomplete" ($errLose -match "locked|already exists|incomplete") "no refusal text"
$rv = Run-BK @("verify", $boxA, "-q")
Check "A3 final box verifies" ($rv.rc -eq 0) ("rc=" + $rv.rc)
Check "A4 no tmp debris after commit" (-not (Test-Path "$boxA.tmp")) "tmp still present"

# ---------------------------------------------------------------- B) kill
Write-Host "=== B: kill backup mid-run (old box must survive byte-identical) ==="
New-Src "bsrc"
$boxB = Join-Path $work "bbox.dbkp"
$r0 = Run-BK @("backup", "bsrc", $boxB, "-q")
if ($r0.rc -ne 0) { Write-Host ("  FATAL: setup backup rc=" + $r0.rc + " " + (OneLine $r0.err)); exit 1 }
$hashBefore = (Get-FileHash $boxB -Algorithm SHA256).Hash
# B1: 大源 --force 覆盖，tmp 出现后中途杀死
New-Src "bsrc" 192
$p3 = Start-BK @("backup", "bsrc", $boxB, "--force")
$deadline = (Get-Date).AddSeconds(60)
while (-not (Test-Path "$boxB.tmp") -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 50 }
if (-not (Test-Path "$boxB.tmp")) { Write-Host "  FATAL: tmp never appeared (backup too fast?)"; exit 1 }
Start-Sleep -Milliseconds 400
try { $p3.Kill() } catch { }
$p3.WaitForExit()
Check "B1a tmp marker present after kill" (Test-Path "$boxB.tmp") "tmp missing"
$hashAfter = (Get-FileHash $boxB -Algorithm SHA256).Hash
Check "B1b old box byte-identical after kill" ($hashAfter -eq $hashBefore) "hash differs"
# B2: verify 必须报告"上次备份未完成"（F6b 残骸 tmp 检测，只报告不删除）
$rV = Run-BK @("verify", $boxB)
Write-Host ("  verify says: " + (OneLine $rV.err))
Check "B2a verify exits non-zero with tmp debris" ($rV.rc -ne 0) ("rc=" + $rV.rc)
Check "B2b verify reports unfinished backup" ($rV.err -match "did not finish|incomplete") "no text"
Check "B2c verify keeps debris (report-only)" (Test-Path "$boxB.tmp") "tmp deleted by verify"
# B3: 不带 --force 重跑必须被拒
$rR = Run-BK @("backup", "bsrc", $boxB)
Write-Host ("  refuse says: " + (OneLine $rR.err))
Check "B3 refuse retry without --force" ($rR.rc -ne 0 -and $rR.err -match "incomplete|--force") ("rc=" + $rR.rc)
# B4: --force 恢复（换小源，快）
New-Src "bsrc"
$rF = Run-BK @("backup", "bsrc", $boxB, "--force")
Check "B4 --force recovers and commits" ($rF.rc -eq 0 -and (Test-Path $boxB)) ("rc=" + $rF.rc + " out=" + (OneLine $rF.err))
Check "B4b tmp cleaned after forced commit" (-not (Test-Path "$boxB.tmp")) "tmp present"
$rV2 = Run-BK @("verify", $boxB, "-q")
Check "B4c recovered box verifies" ($rV2.rc -eq 0) ("rc=" + $rV2.rc)

# ---------------------------------------------------------------- C) empty shell
Write-Host "=== C: empty-shell archive rejected by verify ==="
# 手工构造 512B 合法头（recordCount=1, fileCount=1, payloadSize=0）+ 512B 零载荷
$h = New-Object byte[] 512
[BitConverter]::GetBytes([uint32]0x44424B50).CopyTo($h, 0)   # magic "DBKP" (LE)
[BitConverter]::GetBytes([uint16]1).CopyTo($h, 4)            # version
[BitConverter]::GetBytes([uint16]512).CopyTo($h, 6)          # headerSize
$h[10] = 1                                                   # checksum = crc64
[BitConverter]::GetBytes([uint64]512).CopyTo($h, 20)         # payloadOffset
[BitConverter]::GetBytes([uint64]0).CopyTo($h, 28)           # payloadSize = 0
[BitConverter]::GetBytes([uint64]1).CopyTo($h, 44)           # recordCount = 1
[BitConverter]::GetBytes([uint64]1).CopyTo($h, 52)           # fileCount = 1
$shell = Join-Path $work "shell.dbkp"
$all = New-Object byte[] 1024
[Array]::Copy($h, 0, $all, 0, 512)
[IO.File]::WriteAllBytes($shell, $all)
$rS = Run-BK @("verify", $shell)
Write-Host ("  verify says: " + (OneLine $rS.err))
Check "C1 empty shell verify exits non-zero" ($rS.rc -ne 0) ("rc=" + $rS.rc)

# ---------------------------------------------------------------- D) same-second double write
Write-Host "=== D: schedule double write yields distinct names ==="
New-Src "sssrc"
$ssdir = Join-Path $work "ssdir"
$rD = Run-BK @("schedule", "sssrc", $ssdir, "--every", "1s", "--times", "2", "--prefix", "ss", "-q")
$names = @(Get-ChildItem $ssdir -Filter ss-*.dbkp | ForEach-Object { $_.Name })
Write-Host ("  names: " + ($names -join "   "))
Check "D1 two archives produced" ($rD.rc -eq 0 -and $names.Count -eq 2) ("rc=" + $rD.rc + " count=" + $names.Count)
Check "D2 names are distinct" (($names | Sort-Object -Unique).Count -eq 2) ($names -join ',')
$pat = '^ss-\d{8}-\d{6}-\d{3}(-x\d+)?\.dbkp$'
Check "D3 names carry ms field (F11)" (@($names | Where-Object { $_ -notmatch $pat }).Count -eq 0) ($names -join ',')
Run-BK @("schedule", "sssrc", $ssdir, "--every", "1s", "--times", "1", "--prefix", "ss", "-q") | Out-Null
$names2 = @(Get-ChildItem $ssdir -Filter ss-*.dbkp | ForEach-Object { $_.Name })
Check "D4 third run no overwrite" ($names2.Count -eq 3) ($names2 -join ',')

# ---------------------------------------------------------------- E) F9 self-in-box
Write-Host "=== E: archive inside source, same dest twice (2nd --force) ==="
New-Src "esrc"
$ebox = Join-Path $work "esrc\ebox.dbkp"
$rE1 = Run-BK @("backup", "esrc", $ebox, "-q")
$rE2 = Run-BK @("backup", "esrc", $ebox, "--force", "-q")
Check "E1 both runs succeed" ($rE1.rc -eq 0 -and $rE2.rc -eq 0) ("rc1=" + $rE1.rc + " rc2=" + $rE2.rc)
$rL = Run-BK @("list", $ebox)
$hitBox = @($rL.out -split "`r?`n" | Select-String -SimpleMatch "ebox.dbkp")
Write-Host ("  list hits on ebox.dbkp: " + $hitBox.Count)
Check "E2 new box has no old-box record" ($hitBox.Count -eq 0) (($hitBox | ForEach-Object { $_.Line }) -join '|')
$s1 = (Get-Item $ebox).Length
Run-BK @("backup", "esrc", $ebox, "--force", "-q") | Out-Null
$s2 = (Get-Item $ebox).Length
Check "E3 no size bloat across runs" ($s2 -lt $s1 + $s1 / 2) ("s1=$s1 s2=$s2")

# ---------------------------------------------------------------- summary
Write-Host ("accept_b3: " + $script:pass + " passed, " + $script:fail + " failed")
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
if ($script:fail -gt 0) { exit 1 }
exit 0
