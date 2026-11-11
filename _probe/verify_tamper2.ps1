# Follow-up forensics on the tamper results:
#  (a) byte-level map of the final 512B tail block, per checksum mode
#  (b) does a corrupted PATH record silently rename restored files?
#  (c) does a corrupted MTIME record silently rewrite restored timestamps?
#  (d) does restore validate the per-record crc64 at all (data byte + record
#      size field tampered together)?
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'tampsrc'
$WORK = Join-Path $VIN 'tamp2'
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WORK | Out-Null

$plain = Join-Path $WORK 'p_crc64.dbkp'
& $BK backup $SRC $plain -a none 2>&1 | Out-Null
$sha   = Join-Path $WORK 'p_crc64_copy.dbkp'
Copy-Item $plain $sha
# sha256 / none variants come from the Web-built copies of run #1
$webSha = Join-Path $VIN 'tampwork\api_sha256.dbkp'
$webNon = Join-Path $VIN 'tampwork\api_none.dbkp'
foreach ($p in @($webSha, $webNon)) {
    if (-not (Test-Path $p)) { Write-Output "MISSING $p -- run verify_tamper.ps1 first"; exit 2 }
}

Write-Output '== (a) last 512 bytes of the archive, 8-byte step, flip one byte each =='
foreach ($arc in @(@('crc64(default)', $plain), @('sha256(web)', $webSha), @('none(web)', $webNon))) {
    $by = [IO.File]::ReadAllBytes($arc[1])
    $blind = @(); $hit = 0; $total = 0
    for ($o = $by.Length - 512; $o -lt $by.Length; $o += 8) {
        $total++
        if ($by[$o] -eq 0xFF) { $newV = 0 } else { $newV = $by[$o] -bor 0xFF }
        $t = Join-Path $WORK ("tail_$o.dbkp")
        $c = $by.Clone(); $c[$o] = [byte]$newV
        [IO.File]::WriteAllBytes($t, $c)
        $v = & $BK verify $t 2>&1 | Out-String; $vrc = $LASTEXITCODE
        $dst = Join-Path $WORK ("tailout_$o"); if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        & $BK restore $t $dst '--force' 2>&1 | Out-Null; $rrc = $LASTEXITCODE
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Remove-Item $t -Force -ErrorAction SilentlyContinue
        if ($vrc -eq 0 -and $rrc -eq 0) { $blind += ( '{0}' -f ($o - ($by.Length - 512)) ) } else { $hit++ }
    }
    Write-Output ("  {0,-16} probed={1}  detected={2}  BLIND SPOTS at tail-relative offsets: {3}" -f `
        $arc[0], $total, $hit, ($(if ($blind.Count) { $blind -join ',' } else { 'none' })))
}

Write-Output ''
Write-Output '== (b) PATH record corrupted -> what filenames come out of restore? =='
$by = [IO.File]::ReadAllBytes($plain)
$pathOff = 512 + 114 + 3      # first record, path inline at +114
Write-Output ("  pristine first-entry name bytes: " + ([Text.Encoding]::ASCII.GetString($by, 512 + 114, 24)))
$c = $by.Clone(); $c[$pathOff] = [byte][char]'Z'
$t = Join-Path $WORK 'path_corrupt.dbkp'; [IO.File]::WriteAllBytes($t, $c)
$v = & $BK verify $t 2>&1 | Out-String; $vrc = $LASTEXITCODE
$dst = Join-Path $WORK 'path_out'
$r = & $BK restore $t $dst '--force' 2>&1 | Out-String; $rrc = $LASTEXITCODE
Write-Output ("  verify rc=$vrc  restore rc=$rrc")
Write-Output ("  verify said : " + ((($v -split "`r?`n") | Where-Object { $_ -match 'ERROR|corrupt' } | Select-Object -First 1)))
Write-Output ("  restored names: " + ((Get-ChildItem $dst -Recurse -File | ForEach-Object { $_.Name }) -join ' | '))
Write-Output ("  restore tail  : " + ((($r -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' // '))

Write-Output ''
Write-Output '== (c) MTIME record corrupted -> do restored timestamps silently change? =='
$c2 = $by.Clone()
for ($i = 0; $i -lt 8; $i++) { $c2[512 + 22 + $i] = 0xAA }   # mtimeSec = garbage
$t2 = Join-Path $WORK 'mtime_corrupt.dbkp'; [IO.File]::WriteAllBytes($t2, $c2)
$v2 = & $BK verify $t2 2>&1 | Out-String; $v2rc = $LASTEXITCODE
$dst2 = Join-Path $WORK 'mtime_out'
& $BK restore $t2 $dst2 '--force' 2>&1 | Out-Null; $r2rc = $LASTEXITCODE
Write-Output ("  verify rc=$v2rc  restore rc=$r2rc")
$srcFile = Get-Item (Join-Path $SRC 'small.txt')
$dstFile = Get-Item (Join-Path $dst2 'small.txt') -ErrorAction SilentlyContinue
Write-Output ("  source mtime = " + $srcFile.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss'))
if ($dstFile) { Write-Output ("  restored     = " + $dstFile.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')) }
Write-Output ("  verify msg   : " + ((($v2 -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))

Write-Output ''
Write-Output '== (d) data byte + that record size field both tampered: does restore check per-record crc? =='
# locate mid.bin record by scanning records for a path containing 'mid.bin'
$recStarts = @()
for ($i = 1; $i * 512 -lt $by.Length; $i++) {
    $p = $i * 512
    if ($p + 8 -lt $by.Length -and $by[$p] -eq 0x31 -and $by[$p + 1] -eq 0x44 -and $by[$p + 2] -eq 0x48 -and $by[$p + 3] -eq 0x52) { $recStarts += $p }
}
Write-Output ("  records found: " + $recStarts.Count + "  (offsets " + (($recStarts | ForEach-Object { $_ - 512 } | ForEach-Object { $_ / 512 }) -join ',') + ")")
$mid = $recStarts | Where-Object { [Text.Encoding]::ASCII.GetString($by, $_ + 114, 12) -match 'mid' } | Select-Object -First 1
Write-Output ("  mid.bin record at byte " + $mid)
# find the first data byte that belongs to mid.bin: use the record before it? just flip a byte we know is inside mid.bin payload from run #1 (offset 18893 was detected)
$c3 = $by.Clone()
$c3[18893] = $c3[18893] -bxor 0xFF
# also rewrite the stored crc64 of that record to the crc64 stored in a DIFFERENT record (crc-swap attack)
$other = $recStarts | Where-Object { $_ -ne $mid } | Select-Object -First 1
if ($other) {
    for ($i = 0; $i -lt 8; $i++) { $c3[$mid + 102 + $i] = $by[$other + 102 + $i] }
}
$t3 = Join-Path $WORK 'crc_swap.dbkp'; [IO.File]::WriteAllBytes($t3, $c3)
$v3 = & $BK verify $t3 2>&1 | Out-String; $v3rc = $LASTEXITCODE
$dst3 = Join-Path $WORK 'crc_out'
& $BK restore $t3 $dst3 '--force' 2>&1 | Out-Null; $r3rc = $LASTEXITCODE
Write-Output ("  verify rc=$v3rc  restore rc=$r3rc  restored mid.bin size=" + (Get-Item (Join-Path $dst3 'mid.bin') -ErrorAction SilentlyContinue).Length + " (source=100000)")
Write-Output ("  verify msg: " + ((($v3 -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))

Write-Output ''
Write-Output '== (e) record size field shrunk by 1 (truncate-on-restore attack) =='
$c4 = $by.Clone()
$sz = [BitConverter]::ToInt64($c4, $mid + 86)
[BitConverter]::GetBytes([Int64]($sz - 1024)).CopyTo($c4, $mid + 86)
$t4 = Join-Path $WORK 'size_shrink.dbkp'; [IO.File]::WriteAllBytes($t4, $c4)
$v4 = & $BK verify $t4 2>&1 | Out-String; $v4rc = $LASTEXITCODE
$dst4 = Join-Path $WORK 'size_out'
& $BK restore $t4 $dst4 '--force' 2>&1 | Out-Null; $r4rc = $LASTEXITCODE
$g4 = (Get-Item (Join-Path $dst4 'mid.bin') -ErrorAction SilentlyContinue).Length
Write-Output ("  verify rc=$v4rc  restore rc=$r4rc  mid.bin restored as $g4 bytes (source 100000)  silentTruncation=" + ($r4rc -eq 0 -and $g4 -eq ($sz - 1024)))
Write-Output ("  verify msg: " + ((($v4 -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))
