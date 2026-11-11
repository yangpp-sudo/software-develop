# Focused re-test: corrupt the mid.bin RECORD (not the root-dir record) and see
# what restore actually writes; plus hexdump of the unverified tail region.
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'tampsrc'
$WORK = Join-Path $VIN 'tamp3'
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WORK | Out-Null
$plain = Join-Path $WORK 'base.dbkp'
& $BK backup $SRC $plain -a none 2>&1 | Out-Null
$by = [IO.File]::ReadAllBytes($plain)

function Find-Records($b) {
    $r = @()
    for ($i = 1; $i * 512 -lt $b.Length; $i++) {
        $p = $i * 512
        if ($p + 5 -lt $b.Length -and $b[$p] -eq 0x31 -and $b[$p + 1] -eq 0x44 -and $b[$p + 2] -eq 0x48 -and $b[$p + 3] -eq 0x52) { $r += $p }
    }
    return $r
}
$recs = Find-Records $by
$named = @{}
foreach ($p in $recs) {
    $pl = [BitConverter]::ToUInt16($by, $p + 6)
    $nm = [Text.Encoding]::ASCII.GetString($by, $p + 114, [math]::Min($pl, 40))
    $named[$p] = $nm
}
Write-Output '== records =='
foreach ($p in $recs) { Write-Output ("  @" + $p + "  type=" + [char]$by[$p + 4] + "  path='" + $named[$p] + "'") }
$midRec = ($recs | Where-Object { $named[$_] -match 'mid\.bin' } | Select-Object -First 1)
Write-Output ''
Write-Output ('== (b2) corrupt PATH of record @' + $midRec + ' (byte 3 of the name) ==')
$c = $by.Clone(); $c[$midRec + 114 + 3] = [byte][char]'Z'
$t = Join-Path $WORK 'path_z.dbkp'; [IO.File]::WriteAllBytes($t, $c)
$v = & $BK verify $t 2>&1 | Out-String; $vrc = $LASTEXITCODE
$dst = Join-Path $WORK 'path_z_out'
$r = & $BK restore $t $dst '--force' 2>&1 | Out-String; $rrc = $LASTEXITCODE
Write-Output ("  verify rc=$vrc   restore rc=$rrc")
Write-Output ("  verify msg : " + ((($v -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))
Write-Output ("  names now  : " + ((Get-ChildItem $dst -Recurse -File | ForEach-Object { $_.Name }) -join ' | '))
Write-Output ("  restore msg: " + ((($r -split "`r?`n") | Where-Object { $_ -match 'restored|ok|WARN' } | Select-Object -First 2) -join ' // '))

Write-Output ''
Write-Output '== (c2) corrupt MTIME of that same record (mtimeSec <- 2000-01-01) =='
$c2 = $by.Clone()
$oldT = [BitConverter]::ToInt64($by, $midRec + 22)
$want = ([DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)).ToUnixTimeSeconds()
[BitConverter]::GetBytes([Int64]$want).CopyTo($c2, $midRec + 22)
$t2 = Join-Path $WORK 'mtime_2000.dbkp'; [IO.File]::WriteAllBytes($t2, $c2)
$v2 = & $BK verify $t2 2>&1 | Out-String; $v2rc = $LASTEXITCODE
$dst2 = Join-Path $WORK 'mtime_out'
& $BK restore $t2 $dst2 '--force' 2>&1 | Out-Null; $r2rc = $LASTEXITCODE
$f = Get-Item (Join-Path $dst2 'mid.bin') -ErrorAction SilentlyContinue
Write-Output ("  verify rc=$v2rc  restore rc=$r2rc")
Write-Output ("  source  mid.bin mtime = " + (Get-Item (Join-Path $SRC 'mid.bin')).LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + " (record said " + ([DateTimeOffset]::FromUnixTimeSeconds($oldT)).ToString('yyyy-MM-dd HH:mm:ss') + ")")
if ($f) { Write-Output ("  restored mid.bin mtime = " + $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss') + "   => silentlyRewritten=" + ($f.LastWriteTimeUtc.ToString('yyyy') -eq '2000')) }
Write-Output ("  verify msg: " + ((($v2 -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))

Write-Output ''
Write-Output '== (a2) what lives in the last 512 bytes, and which part nobody checks =='
foreach ($pair in @(@('crc64', $plain), @('sha256', (Join-Path $VIN 'tampwork\api_sha256.dbkp')), @('none', (Join-Path $VIN 'tampwork\api_none.dbkp')))) {
    if (-not (Test-Path $pair[1])) { continue }
    $b = [IO.File]::ReadAllBytes($pair[1])
    $tail = $b[($b.Length - 512)..($b.Length - 1)]
    $nz = @(); for ($i = 0; $i -lt 512; $i += 16) { if (@($tail[$i..($i + 15)] | Where-Object { $_ -ne 0 }).Count -gt 0) { $nz += ('{0:X3}' -f $i) } }
    Write-Output ("  --- mode " + $pair[0] + " : last-512 non-zero 16B rows at tail offsets " + ($nz -join ','))
    for ($i = 0; $i -lt 512; $i += 32) {
        $row = $tail[$i..([math]::Min($i + 31, 511))]
        $hex = (($row | ForEach-Object { '{0:x2}' -f $_ }) -join '')
        $asc = -join ($row | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
        Write-Output ("      {0:X3}  {1}  {2}" -f $i, $hex, $asc)
    }
}
