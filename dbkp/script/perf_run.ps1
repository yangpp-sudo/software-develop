# ============================================================================
#  perf_run.ps1 -- 性能测试（批次10 任务C / 老师 p38 四类型之"性能测试"）
#  做法：10MB 与 50MB 样本各做 3 轮"备份 + 还原"，记录耗时、吞吐、压缩率。
#  usage: powershell -ExecutionPolicy Bypass -File script/perf_run.ps1
#  产物：doc/perf/perf_run.txt
#  可重复运行：每次都在 %TEMP% 下新建独立工作目录并在结束时清理。
# ============================================================================
$ErrorActionPreference = 'Stop'

# $PSScriptRoot 在部分调用方式下为空，回退到脚本自身路径
$Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
        elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path }
        else { (Get-Location).Path }
$BK   = Join-Path $Root 'bin\bk.exe'
if (!(Test-Path $BK)) { Write-Host "build first: $BK not found"; exit 1 }

$OutDir = Join-Path $Root 'doc\perf'
if (!(Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$Out    = Join-Path $OutDir 'perf_run.txt'

$work = Join-Path $env:TEMP ('dbkp_perf_run_' + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
# Set-Location 不改 .NET 当前目录，两者必须一起设
Set-Location $work
[Environment]::CurrentDirectory = $work

$MB = 1024 * 1024

function New-Sample([string]$dir, [int]$sizeMB) {
    # 40% 高重复文本 + 60% 伪随机：既体现压缩收益又不至于压到 0
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $total = $sizeMB * $MB
    $repLen = [int]($total * 0.4)
    $rndLen = $total - $repLen
    $line = [Text.Encoding]::ASCII.GetBytes('The quick brown fox jumps over the lazy dog. ')
    $buf = New-Object byte[] $repLen
    for ($i = 0; $i -lt $buf.Length; $i += $line.Length) {
        [Array]::Copy($line, 0, $buf, $i, [Math]::Min($line.Length, $buf.Length - $i))
    }
    [IO.File]::WriteAllBytes((Join-Path $dir 'text.dat'), $buf)
    $r = New-Object Random(20261111)          # 固定种子，保证可复现
    $fs = [IO.File]::Create((Join-Path $dir 'rand.dat'))
    try {
        $chunk = New-Object byte[] 65536
        $left = $rndLen
        while ($left -gt 0) {
            $n = [Math]::Min($chunk.Length, $left)
            $r.NextBytes($chunk)
            $fs.Write($chunk, 0, $n)
            $left -= $n
        }
    } finally { $fs.Dispose() }
    # 再放两个小文件，模拟真实目录里多条目场景
    [IO.File]::WriteAllText((Join-Path $dir 'a.txt'), 'alpha' * 200)
    [IO.File]::WriteAllText((Join-Path $dir 'b.txt'), 'beta'  * 200)
    return (Get-ChildItem $dir -File | Measure-Object Length -Sum).Sum
}

function TimeIt([scriptblock]$b) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $code = & $b
    $sw.Stop()
    return [pscustomobject]@{ sec = $sw.Elapsed.TotalSeconds; code = $code }
}

$rows = @()
foreach ($sizeMB in @(10, 50)) {
    $src = Join-Path $work ("src_$sizeMB")
    $rawBytes = New-Sample $src $sizeMB
    for ($round = 1; $round -le 3; $round++) {
        $arc = Join-Path $work ("arc_{0}_{1}.dbkp" -f $sizeMB, $round)
        $dst = Join-Path $work ("out_{0}_{1}" -f $sizeMB, $round)
        $b = TimeIt { & $BK backup $src $arc -a lzhuff --force -q 2>&1 | Out-Null; $LASTEXITCODE }
        if ($b.code -ne 0) { Write-Host "backup failed size=$sizeMB round=$round code=$($b.code)"; $b.code | Out-File (Join-Path $work 'err.txt'); exit 1 }
        $r = TimeIt { & $BK restore $arc $dst --force -q 2>&1 | Out-Null; $LASTEXITCODE }
        if ($r.code -ne 0) { Write-Host "restore failed size=$sizeMB round=$round code=$($r.code)"; exit 1 }
        $stored = (Get-Item $arc).Length
        $outBytes = (Get-ChildItem $dst -File -Recurse | Measure-Object Length -Sum).Sum
        if ($outBytes -ne $rawBytes) { Write-Host "size mismatch after restore: $outBytes != $rawBytes"; exit 1 }
        $rows += [pscustomobject]@{
            sample      = ('{0}MB' -f $sizeMB)
            round       = $round
            rawMB       = [Math]::Round($rawBytes / $MB, 2)
            storedMB    = [Math]::Round($stored / $MB, 2)
            ratio       = ('{0:P1}' -f ($stored / $rawBytes))
            backupSec   = [Math]::Round($b.sec, 3)
            restoreSec  = [Math]::Round($r.sec, 3)
            backupMBs   = [Math]::Round(($rawBytes / $MB) / $b.sec, 2)
            restoreMBs  = [Math]::Round(($rawBytes / $MB) / $r.sec, 2)
        }
        Remove-Item -Recurse -Force $dst -EA SilentlyContinue
        Remove-Item -Force $arc -EA SilentlyContinue
    }
}

$head = @(
    '============================================================================'
    ' dbkp 性能测试（批次10 任务C）'
    (' 运行时间 : ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    (' 编译器   : MinGW-w64 GCC 8.1.0 (x86_64-posix-seh-rev0)')
    (' 被测程序 : ' + $BK)
    ' 压缩算法 : -a lzhuff (LZ77 + Huffman)'
    ' 样本构成 : 40% 高重复文本 + 60% 伪随机(固定种子) + 2 个小文本文件'
    ' 指标口径 : 耗时=bk.exe 进程墙钟时间；压缩率=归档字节/原始字节'
    ' 说明     : VS「性能探查器」CPU 采样截图需人工在 IDE 内完成，'
    '            命令行环境无法产出，已在对账报告中如实登记。'
    '============================================================================'
    ''
)
$table = $rows | Format-Table -AutoSize | Out-String -Width 200
$sum = @(
    '--- 分组小结 ---'
)
foreach ($sizeMB in @(10, 50)) {
    $g = $rows | Where-Object { $_.sample -eq ('{0}MB' -f $sizeMB) }
    $sum += ('{0}MB 样本：平均备份 {1}s / 平均还原 {2}s / 平均吞吐 {3} MB/s / 平均压缩率 {4}' -f `
        $sizeMB,
        [Math]::Round(($g | Measure-Object backupSec -Average).Average, 3),
        [Math]::Round(($g | Measure-Object restoreSec -Average).Average, 3),
        [Math]::Round(($g | Measure-Object backupMBs -Average).Average, 2),
        [Math]::Round(($g | Measure-Object storedMB -Average).Average / $sizeMB * 100, 1))
}
$sum += ''
$sum += '--- 逐轮明细 ---'
$text = ($head -join "`r`n") + "`r`n" + $table + "`r`n" + ($sum -join "`r`n") + "`r`n"
[IO.File]::WriteAllText($Out, $text, (New-Object Text.UTF8Encoding($true)))
Write-Host $text
Write-Host ('written: ' + $Out)

Set-Location $Root
Remove-Item -Recurse -Force $work -EA SilentlyContinue
exit 0