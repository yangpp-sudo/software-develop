# ============================================================================
#  perf_recheck.ps1 -- NF-04 分档指标的复测脚本
#
#  与 script/perf.ps1 完全相同的数据构造与计时口径（48 MB = 高重复文本 16 MB
#  + 随机 16 MB + 半随机 16 MB，进程墙钟时间），另外补三项 perf.ps1 没有的
#  配置：huffman+aes256 的还原吞吐、lzhuff+chacha20 全开、以及把 copy-mode
#  的还原也计时。产物写 doc/perf-raw-recheck.txt，不覆盖 doc/perf-raw.txt。
#
#  usage: powershell -File script/perf_recheck.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$BK   = Join-Path $root "bin\bk.exe"
if (!(Test-Path $BK)) { Write-Host "build first"; exit 1 }

$work = Join-Path $env:TEMP ("dbkp_perfchk_" + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
[Environment]::CurrentDirectory = $work

function TimeIt([scriptblock]$b) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $b | Out-Null
    $sw.Stop()
    return $sw.Elapsed.TotalSeconds
}

function Row($algo, $t, $t2, $stored) {
    return [pscustomobject]@{ algo = $algo; backupSec = [Math]::Round($t, 2)
        restoreSec = [Math]::Round($t2, 2); storedMB = [Math]::Round($stored / 1MB, 1)
        backupMBs = [Math]::Round($totalRaw / 1MB / $t, 1)
        restoreMBs = $(if ($t2 -gt 0) { [Math]::Round($totalRaw / 1MB / $t2, 1) } else { 0 }) }
}

# ---- 构造测试数据：与 perf.ps1 一致 ---------------------------------------
$MB = 1024 * 1024
$rep = New-Object byte[] (16 * $MB)
$line = [Text.Encoding]::ASCII.GetBytes("The quick brown fox jumps over the lazy dog. " * 2)
for ($i = 0; $i -lt $rep.Length; $i += $line.Length) {
    [Array]::Copy($line, 0, $rep, $i, [Math]::Min($line.Length, $rep.Length - $i))
}
$rnd = New-Object byte[] (16 * $MB)
(New-Object Random).NextBytes($rnd)
$semi = New-Object byte[] (16 * $MB)
for ($i = 0; $i -lt $semi.Length; $i += 64) {
    $cut = [Math]::Min(32, $semi.Length - $i)
    [Array]::Copy($rep, $i % $line.Length, $semi, $i, $cut)
    [Array]::Copy($rnd, $i % $rnd.Length, $semi, ($i + $cut), [Math]::Min(32, $semi.Length - $i - $cut))
}
New-Item -ItemType Directory -Force -Path "src" | Out-Null
[IO.File]::WriteAllBytes("$work\src\text.dat", $rep)
[IO.File]::WriteAllBytes("$work\src\rand.dat", $rnd)
[IO.File]::WriteAllBytes("$work\src\semi.dat", $semi)
$script:totalRaw = (Get-ChildItem src -File | Measure-Object Length -Sum).Sum

$rows = @()

# ---- 纯压缩档 -------------------------------------------------------------
foreach ($cfg in @('none', 'huffman', 'lz77', 'lzhuff', 'rle')) {
    $t = TimeIt { & $BK backup src "p.dbkp" -a $cfg --force -q }
    $stored = (Get-Item "p.dbkp").Length
    $t2 = TimeIt { & $BK restore "p.dbkp" out --force -q }
    Remove-Item -Recurse -Force out -EA SilentlyContinue
    $rows += Row $cfg $t $t2 $stored
}

# ---- 纯加密档 -------------------------------------------------------------
foreach ($cfg in @('aes256', 'chacha20')) {
    $t = TimeIt { & $BK backup src "p.dbkp" -a none -c $cfg -p 'S3cret!' --force -q }
    $t2 = TimeIt { & $BK restore "p.dbkp" out --force -p 'S3cret!' -q }
    Remove-Item -Recurse -Force out -EA SilentlyContinue
    $rows += Row "none+$cfg" $t $t2 (Get-Item "p.dbkp").Length
}

# ---- 压缩 + 加密全开档（NF-04 的判定对象）--------------------------------
foreach ($pair in @('huffman aes256', 'lzhuff chacha20')) {
    $p = $pair -split ' '
    $t = TimeIt { & $BK backup src "p.dbkp" -a $p[0] -c $p[1] -p 'S3cret!' --force -q }
    $t2 = TimeIt { & $BK restore "p.dbkp" out --force -p 'S3cret!' -q }
    Remove-Item -Recurse -Force out -EA SilentlyContinue
    $rows += Row "$($p[0])+$($p[1])" $t $t2 (Get-Item "p.dbkp").Length
}

# ---- 复制模式（最快链路，只测备份）---------------------------------------
$t = TimeIt { & $BK backup src cpy --copy -q }
$rows += Row 'copy-mode' $t 0 0

$head = "raw=$totalRaw bytes  machine=$env:COMPUTERNAME  cpu=$env:PROCESSOR_IDENTIFIER  time=$(Get-Date)"
New-Item -ItemType Directory -Force -Path (Join-Path $root "doc") | Out-Null
$outFile = Join-Path $root "doc\perf-raw-recheck.txt"
$head | Out-File -Encoding utf8 $outFile
$rows | Format-Table -AutoSize | Out-String -Width 200 | Add-Content -Encoding utf8 $outFile
Write-Host $head
$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Set-Location $root
Remove-Item -Recurse -Force $work -EA SilentlyContinue
