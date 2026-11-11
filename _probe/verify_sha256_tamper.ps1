# P0 nail-down: sha256 整卷摘要真正落盘后，record 元数据篡改（改名/mtime/size）
# 必须被 verify 与 restore 前置校验拦下；--skip-payload-verify 是逃生舱。
# 自建 fixture，不依赖其它脚本留下的临时状态。纯测试，不碰工程树。
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_sha256_tamper'
if (Test-Path $VIN) { Remove-Item $VIN -Recurse -Force }
$SRC  = Join-Path $VIN 'src'; $WORK = Join-Path $VIN 'work'
New-Item -ItemType Directory -Force -Path $SRC, (Join-Path $SRC 'sub'), $WORK | Out-Null
Set-Content (Join-Path $SRC 'top.txt')      -Value ('head ' * 5000)   -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'sub\mid.bin')  -Value ('mid data ' * 20000) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'tail.txt')     -Value ('tail ' * 3000)   -Encoding ascii -NoNewline

$arc = Join-Path $WORK 's256.dbkp'
& $BK backup $SRC $arc -a none --checksum sha256 2>&1 | Out-String | Write-Output
Write-Output ("backup rc=" + $LASTEXITCODE)

$by = [IO.File]::ReadAllBytes($arc)
$hdrSize = [BitConverter]::ToUInt16($by, 6)
$payloadOff = [BitConverter]::ToInt64($by, 20)
Write-Output ("headerSize=" + $hdrSize + " (expect 1024)  payloadOffset=" + $payloadOff + " (expect 1024)")
Write-Output '----- bk info -----'
& $BK info $arc 2>&1 | Out-String | Write-Output

# 干净卷：verify 与 restore 都必须过，且还原内容与源一致
& $BK verify $arc 2>&1 | Out-Null; Write-Output ("clean verify rc=" + $LASTEXITCODE + " (expect 0)")
$rd = Join-Path $WORK 'clean_out'
& $BK restore $arc $rd '--force' 2>&1 | Out-Null; $crc = $LASTEXITCODE
$srcHash = (Get-FileHash -Algorithm SHA256 (Join-Path $SRC 'sub\mid.bin')).Hash
$dstHash = (Get-FileHash -Algorithm SHA256 (Join-Path $rd 'sub\mid.bin') -ErrorAction SilentlyContinue).Hash
Write-Output ("clean restore rc=" + $crc + " (expect 0)  mid.bin round-trip=" + ($srcHash -eq $dstHash))

# 定位 sub/mid.bin 的记录块（payload 从 1024 起 = 第 2 个 512B 块）
$recs = @()
for ($i = 2; $i * 512 -lt $by.Length; $i++) {
    $p = $i * 512
    if ($by[$p] -eq 0x31 -and $by[$p + 1] -eq 0x44 -and $by[$p + 2] -eq 0x48 -and $by[$p + 3] -eq 0x52) { $recs += $p }
}
$mid = $recs | Where-Object { [Text.Encoding]::ASCII.GetString($by, $_ + 114, 7) -match 'mid' } | Select-Object -First 1
Write-Output ("mid.bin record offset = " + $mid)

function Attack($name, [scriptblock]$mutator) {
    $c = $by.Clone(); & $mutator $c $mid
    $t = Join-Path $WORK ("atk_$name.dbkp"); [IO.File]::WriteAllBytes($t, $c)
    & $BK verify $t 2>&1 | Out-Null; $vrc = $LASTEXITCODE
    $od = Join-Path $WORK "atk_$name.out"; if (Test-Path $od) { Remove-Item $od -Recurse -Force }
    $rr = & $BK restore $t $od '--force' 2>&1 | Out-String; $rrc = $LASTEXITCODE
    $err = (($rr -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)
    Write-Output ("  {0,-8} verify rc={1} restore rc={2}  blocked={3}  {4}" -f `
        $name, $vrc, $rrc, (($vrc -ne 0) -and ($rrc -ne 0)), $err)
}

Write-Output '----- 篡改矩阵（sha256 整卷摘要必须全部拦下）-----'
Attack 'rename' { param($c, $m) $c[$m + 114 + 4] = [byte][char]'Z' }
Attack 'mtime'  { param($c, $m) [BitConverter]::GetBytes([Int64]946684800).CopyTo($c, $m + 22) }
Attack 'size'   { param($c, $m) [BitConverter]::GetBytes([Int64]1).CopyTo($c, $m + 86) }
Attack 'data'   { param($c, $m) $c[$m + 600] = $c[$m + 600] -bxor 0xFF }

# 逃生舱：跳过整卷校验后，被改名的卷能强行还原（验证 --skip-payload-verify 生效）
$t2 = Join-Path $WORK 'atk_rename.dbkp'
$od2 = Join-Path $WORK 'skip_out'; if (Test-Path $od2) { Remove-Item $od2 -Recurse -Force }
& $BK restore $t2 $od2 '--force' '--skip-payload-verify' 2>&1 | Out-Null
Write-Output ("  skip-payload-verify restore rc=" + $LASTEXITCODE + " (expect 0：逃生舱可用)")
