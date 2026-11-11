# Nail-down test: on the archives created with checksum=sha256 and checksum=none,
# corrupt metadata fields of the mid.bin record and see if anything reacts.
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$WORK = Join-Path $VIN 'tamp4'
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Force -Path $WORK | Out-Null

function Probe($label, $srcArc) {
    Write-Output ('===== ' + $label + ' =====')
    $by = [IO.File]::ReadAllBytes($srcArc)
    $recs = @()
    for ($i = 1; $i * 512 -lt $by.Length; $i++) {
        $p = $i * 512
        if ($p + 5 -lt $by.Length -and $by[$p] -eq 0x31 -and $by[$p + 1] -eq 0x44 -and $by[$p + 2] -eq 0x48 -and $by[$p + 3] -eq 0x52) { $recs += $p }
    }
    $mid = $recs | Where-Object { [Text.Encoding]::ASCII.GetString($by, $_ + 114, 12) -match 'mid' } | Select-Object -First 1
    if (-not $mid) { Write-Output '  mid.bin record not found'; return }
    Write-Output ("  checksum byte in header = " + $by[36] + "   (0=none 1=crc64 2=sha256);  mid.bin record @" + $mid)

    # 1) rename attack
    $c = $by.Clone(); $c[$mid + 114 + 3] = [byte][char]'Z'
    $t = Join-Path $WORK 'z.dbkp'; [IO.File]::WriteAllBytes($t, $c)
    $v = & $BK verify $t 2>&1 | Out-String; $vrc = $LASTEXITCODE
    $d = Join-Path $WORK 'z_out'; if (Test-Path $d) { Remove-Item $d -Recurse -Force }
    & $BK restore $t $d '--force' 2>&1 | Out-Null; $rrc = $LASTEXITCODE
    $names = (Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) -join ' | '
    Write-Output ("  [rename ] verify rc=$vrc  restore rc=$rrc  names: " + $names)

    # 2) timestamp attack
    $c2 = $by.Clone()
    [BitConverter]::GetBytes([Int64]946684800).CopyTo($c2, $mid + 22)   # 2000-01-01
    $t2 = Join-Path $WORK 'm.dbkp'; [IO.File]::WriteAllBytes($t2, $c2)
    $v2 = & $BK verify $t2 2>&1 | Out-String; $v2rc = $LASTEXITCODE
    $d2 = Join-Path $WORK 'm_out'; if (Test-Path $d2) { Remove-Item $d2 -Recurse -Force }
    & $BK restore $t2 $d2 '--force' 2>&1 | Out-Null; $r2rc = $LASTEXITCODE
    $f = Get-Item (Join-Path $d2 'mid.bin') -ErrorAction SilentlyContinue
    Write-Output ("  [mtime  ] verify rc=$v2rc  restore rc=$r2rc  restored mtime = " + $(if ($f) { $f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm') } else { 'n/a' }))

    # 3) data byte attack (should always be caught by per-record crc)
    $c3 = $by.Clone(); $c3[$mid + 600] = $c3[$mid + 600] -bxor 0xFF
    $t3 = Join-Path $WORK 'd.dbkp'; [IO.File]::WriteAllBytes($t3, $c3)
    $v3 = & $BK verify $t3 2>&1 | Out-String; $v3rc = $LASTEXITCODE
    $d3 = Join-Path $WORK 'd_out'; if (Test-Path $d3) { Remove-Item $d3 -Recurse -Force }
    & $BK restore $t3 $d3 '--force' 2>&1 | Out-Null; $r3rc = $LASTEXITCODE
    Write-Output ("  [data   ] verify rc=$v3rc  restore rc=$r3rc  " + ((($v3 -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)))
}

Probe 'checksum=sha256 (created by Web)' (Join-Path $VIN 'tampwork\api_sha256.dbkp')
Write-Output ''
Probe 'checksum=none (created by Web)'  (Join-Path $VIN 'tampwork\api_none.dbkp')
Write-Output ''
Probe 'checksum=crc64 (CLI default)'    (Join-Path $VIN 'tamp3\base.dbkp')
