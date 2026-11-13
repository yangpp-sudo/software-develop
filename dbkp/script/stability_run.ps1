# ============================================================================
#  stability_run.ps1 -- 稳定性测试（批次10 任务C）
#  ① round-trip：备份 -> 校验 -> 还原 -> 逐字节对比，连续 50 轮，失败即停；
#  ② 定时备份：bk schedule --every 5s --times 20 --keep 3，观察保留策略与
#     连续运行稳定性。
#  usage: powershell -ExecutionPolicy Bypass -File script/stability_run.ps1
#         powershell -File script/stability_run.ps1 -SkipSchedule   # 只跑 50 轮
#  产物：doc/perf/stability_run.txt
# ============================================================================
param([switch]$SkipSchedule, [int]$Rounds = 50)
$ErrorActionPreference = 'Stop'

$Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
        elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
        else { (Get-Location).Path }
$BK = Join-Path $Root 'bin\bk.exe'
if (!(Test-Path $BK)) { Write-Host "build first: $BK not found"; exit 1 }

$OutDir = Join-Path $Root 'doc\perf'
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$Out = Join-Path $OutDir 'stability_run.txt'

$work = Join-Path $env:TEMP ('dbkp_stab_' + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
[Environment]::CurrentDirectory = $work

$log = New-Object Collections.Generic.List[string]
function Say([string]$m) { Write-Host $m; $log.Add($m) }

Say '============================================================================'
Say (' dbkp 稳定性测试  运行时间: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Say (' 被测程序: ' + $BK)
Say (' 轮次: {0} 轮 round-trip；定时备份 --every 5s --times 20 --keep 3' -f $Rounds)
Say ' 失败即停：任一轮退出码非 0 或逐字节对比不一致立即终止并记录轮号'
Say '============================================================================'
Say ''

# ---- 固定样本（每轮内容随轮号变化，覆盖"内容变更后再备份"路径）-------------
$src = Join-Path $work 'src'
New-Item -ItemType Directory -Force -Path $src | Out-Null
function Write-Sample([int]$n) {
    $r = New-Object Random($n)
    $line = [Text.Encoding]::ASCII.GetBytes(('round{0} ' -f $n) + 'stable payload block. ')
    $buf = New-Object byte[] (1024 * 1024)
    for ($i = 0; $i -lt $buf.Length; $i += $line.Length) {
        [Array]::Copy($line, 0, $buf, $i, [Math]::Min($line.Length, $buf.Length - $i))
    }
    [IO.File]::WriteAllBytes((Join-Path $src 'payload.dat'), $buf)
    $chunk = New-Object byte[] 65536
    $fs = [IO.File]::Create((Join-Path $src 'noise.bin'))
    try { for ($k = 0; $k -lt 8; $k++) { $r.NextBytes($chunk); $fs.Write($chunk, 0, $chunk.Length) } }
    finally { $fs.Dispose() }
    [IO.File]::WriteAllText((Join-Path $src 'note.txt'), ("round $n marker`r`n" * 32))
}

function Compare-Tree([string]$a, [string]$b) {
    # 逐字节对比两目录（文件名+内容），返回 $null 表示一致
    $fa = Get-ChildItem $a -File -Recurse | Sort-Object { $_.FullName.Substring($a.Length) }
    $fb = Get-ChildItem $b -File -Recurse | Sort-Object { $_.FullName.Substring($b.Length) }
    if ($fa.Count -ne $fb.Count) { return "entry count $($fa.Count) != $($fb.Count)" }
    for ($i = 0; $i -lt $fa.Count; $i++) {
        $ra = $fa[$i].FullName.Substring($a.Length)
        $rb = $fb[$i].FullName.Substring($b.Length)
        if ($ra -ne $rb) { return "name '$ra' != '$rb'" }
        if ($fa[$i].Length -ne $fb[$i].Length) { return "$ra size $($fa[$i].Length) != $($fb[$i].Length)" }
        $ha = (Get-FileHash -Algorithm SHA256 -LiteralPath $fa[$i].FullName).Hash
        $hb = (Get-FileHash -Algorithm SHA256 -LiteralPath $fb[$i].FullName).Hash
        if ($ha -ne $hb) { return "$ra content mismatch" }
    }
    return $null
}

# ---- ① 50 轮 round-trip -----------------------------------------------------
Say '--- ① round-trip 50 轮：backup -> verify -> restore -> 逐字节对比 ---'
$failRound = 0
$swAll = [Diagnostics.Stopwatch]::StartNew()
for ($n = 1; $n -le $Rounds; $n++) {
    Write-Sample $n
    $arc = Join-Path $work ('rt_{0}.dbkp' -f $n)
    $dst = Join-Path $work ('rt_out_{0}' -f $n)
    Remove-Item -Force $arc -EA SilentlyContinue
    Remove-Item -Recurse -Force $dst -EA SilentlyContinue

    & $BK backup $src $arc -a lzhuff --force -q 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failRound = $n; Say ("FAIL round {0}: backup exit={1}" -f $n, $LASTEXITCODE); break }
    & $BK verify $arc -q 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failRound = $n; Say ("FAIL round {0}: verify exit={1}" -f $n, $LASTEXITCODE); break }
    & $BK restore $arc $dst --force -q 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $failRound = $n; Say ("FAIL round {0}: restore exit={1}" -f $n, $LASTEXITCODE); break }
    $diff = Compare-Tree $src $dst
    if ($diff) { $failRound = $n; Say ("FAIL round {0}: byte compare -> $diff"); break }
    if ($n % 10 -eq 0 -or $n -le 3) {
        Say ("round {0,2}/{1} OK  archive={2} KB" -f $n, $Rounds, [Math]::Round((Get-Item $arc).Length / 1KB, 1))
    }
    Remove-Item -Recurse -Force $dst -EA SilentlyContinue
    Remove-Item -Force $arc -EA SilentlyContinue
}
$swAll.Stop()
if ($failRound -gt 0) {
    Say ("round-trip 结果: 失败于第 $failRound 轮（失败即停，已中止后续轮次）")
} else {
    Say ("round-trip 结果: {0} 轮全部通过，总耗时 {1:N1}s，平均 {2:N2}s/轮" -f `
        $Rounds, $swAll.Elapsed.TotalSeconds, ($swAll.Elapsed.TotalSeconds / $Rounds))
}
Say ''

# ---- ② 定时备份 20 次 keep=3 ------------------------------------------------
if ($SkipSchedule) {
    Say '--- ② 定时备份：本次调用以 -SkipSchedule 跳过 ---'
} elseif ($failRound -gt 0) {
    Say '--- ② 定时备份：因 ① 失败即停，跳过 ---'
} else {
    Say '--- ② 定时备份 bk schedule --every 5s --times 20 --keep 3 ---'
    $sSrc = Join-Path $work 'sched_src'
    $sDst = Join-Path $work 'sched_dst'
    New-Item -ItemType Directory -Force -Path $sSrc, $sDst | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $sSrc 'data.bin'), (New-Object byte[] (256 * 1024)))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    # 定时备份跑在后台 Job 里，主线程每 2s 改写源文件，制造真实增量
    # 注意：schedule 子命令不接受 --force（会报 unknown option 并退出码 2），
    #       归档名带时间戳，天然不冲突。
    $job = Start-Job -ScriptBlock {
        param($bk, $s, $d)
        $out = & $bk schedule $s $d --every 5s --times 20 --keep 3 2>&1
        [pscustomobject]@{ code = $LASTEXITCODE; text = ($out -join "`r`n") }
    } -ArgumentList $BK, $sSrc, $sDst
    $mutate = 0
    while ($job.State -eq 'Running') {
        $mutate++
        $r = New-Object Random($mutate)
        $buf = New-Object byte[] (4096)
        $r.NextBytes($buf)
        [IO.File]::WriteAllBytes((Join-Path $sSrc 'live.bin'), $buf)
        Start-Sleep -Milliseconds 2000
        if ($sw.Elapsed.TotalSeconds -gt 240) { Stop-Job $job; break }
    }
    $res = Receive-Job $job
    Remove-Job $job -Force
    if (-not $res) { $res = [pscustomobject]@{ code = -1; text = "timeout >240s, job stopped" } }
    $sw.Stop()
    Say ("schedule 退出码: {0}   实际耗时: {1:N1}s（理论 ~95s：20 次 x 5s 间隔）" -f $res.code, $sw.Elapsed.TotalSeconds)
    if ($res.text) { Say ("schedule 输出（末 15 行）:`r`n" + (($res.text -split "`r?`n" | Select-Object -Last 15) -join "`r`n")) }
    $kept = @(Get-ChildItem $sDst -File -EA SilentlyContinue | Where-Object { $_.Name -like '*.dbkp' })
    Say ("归档目录内 .dbkp 数量: {0}  （--keep 3 期望 <= 3）" -f $kept.Count)
    $tmp = @(Get-ChildItem $sDst -File -EA SilentlyContinue | Where-Object { $_.Name -like '*.tmp' })
    Say ("残留 .tmp 数量: {0}  （期望 0，无半成品输出）" -f $tmp.Count)
    if ($kept.Count -gt 3) { $failRound = -1000; Say 'FAIL: keep 策略未生效' }
    if ($tmp.Count -ne 0)  { $failRound = -1001; Say 'FAIL: 存在 .tmp 残骸' }
}

Say ''
Say '============================================================================'
if ($failRound -eq 0) { Say ' 稳定性测试结论: 全部通过' } else { Say " 稳定性测试结论: 失败（见上文轮号）" }
Say ' 内存佐证：VS「诊断工具」附加 bkd.exe/bk.exe 采集内存曲线需人工在 IDE 内'
Say '          操作，命令行环境无法产出，已在对账报告中如实登记。'
Say '============================================================================'

$text = ($log -join "`r`n") + "`r`n"
[IO.File]::WriteAllText($Out, $text, (New-Object Text.UTF8Encoding($true)))
Write-Host ('written: ' + $Out)

Set-Location $Root
Remove-Item -Recurse -Force $work -EA SilentlyContinue
if ($failRound -ne 0) { exit 1 } else { exit 0 }
