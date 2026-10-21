# ============================================================================
#  perf.ps1 -- 吞吐性能测量（给测试报告的"性能测试"章节提供真实数据）
#  usage: powershell -File script/perf.ps1
#  产物：控制台表格 + doc/perf-raw.txt
# ============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$BK   = Join-Path $root "bin\bk.exe"
if (!(Test-Path $BK)) { Write-Host "build first"; exit 1 }

$work = Join-Path $env:TEMP ("dbkp_perf_" + $PID)
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
[Environment]::CurrentDirectory = $work

function TimeIt([scriptblock]$b) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $b | Out-Null
    $sw.Stop()
    return $sw.Elapsed.TotalSeconds
}

# ---- 构造测试数据：文本(高重复) / 随机(不可压) / 半随机 ---------------------
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
$totalRaw = (Get-ChildItem src -File | Measure-Object Length -Sum).Sum

$rows = @()
foreach ($cfg in @('none', 'huffman', 'lz77', 'lzhuff', 'rle')) {
    $t = TimeIt { & $BK backup src "p.dbkp" -a $cfg -q }
    $stored = (Get-Item "p.dbkp").Length
    $t2 = TimeIt { & $BK restore "p.dbkp" out --force -q }
    Remove-Item -Recurse -Force out -EA SilentlyContinue
    $rows += [pscustomobject]@{ algo = $cfg; backupSec = [Math]::Round($t, 2);
        restoreSec = [Math]::Round($t2, 2); storedMB = [Math]::Round($stored / 1MB, 1);
        backupMBs = [Math]::Round($totalRaw / 1MB / $t, 1); restoreMBs = [Math]::Round($totalRaw / 1MB / $t2, 1) }
}
foreach ($cfg in @('aes256', 'chacha20')) {
    $t = TimeIt { & $BK backup src "p.dbkp" -a none -c $cfg -p 'S3cret!' -q }
    $t2 = TimeIt { & $BK restore "p.dbkp" out --force -p 'S3cret!' -q }
    Remove-Item -Recurse -Force out -EA SilentlyContinue
    $rows += [pscustomobject]@{ algo = "none+$cfg"; backupSec = [Math]::Round($t, 2);
        restoreSec = [Math]::Round($t2, 2); storedMB = [Math]::Round((Get-Item "p.dbkp").Length / 1MB, 1);
        backupMBs = [Math]::Round($totalRaw / 1MB / $t, 1); restoreMBs = [Math]::Round($totalRaw / 1MB / $t2, 1) }
}
$t = TimeIt { & $BK backup src "p.dbkp" -a huffman -c aes256 -p 'S3cret!' -q }
$rows += [pscustomobject]@{ algo = 'huffman+aes256'; backupSec = [Math]::Round($t, 2);
    restoreSec = 0; storedMB = [Math]::Round((Get-Item "p.dbkp").Length / 1MB, 1);
    backupMBs = [Math]::Round($totalRaw / 1MB / $t, 1); restoreMBs = 0 }
$rows += [pscustomobject]@{ algo = 'copy-mode'; backupSec = (TimeIt { & $BK backup src cpy --copy -q } | % { [Math]::Round($_, 2) });
    restoreSec = (TimeIt { & $BK restore cpy cpy2 --force -q } | % { [Math]::Round($_, 2) });
    storedMB = 0; backupMBs = [Math]::Round($totalRaw / 1MB / (TimeIt { & $BK backup src cpy3 --copy -q }), 1); restoreMBs = 0 }

$rows | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
New-Item -ItemType Directory -Force -Path (Join-Path $root "doc") | Out-Null
$outFile = Join-Path $root "doc\perf-raw.txt"
"raw=$totalRaw bytes  machine=$env:COMPUTERNAME  time=$(Get-Date)" | Out-File -Encoding utf8 $outFile
$rows | Format-Table -AutoSize | Out-String -Width 200 | Add-Content -Encoding utf8 $outFile
Set-Location $root
Remove-Item -Recurse -Force $work -EA SilentlyContinue
