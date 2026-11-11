# P0 nail-down (all checksum modes), self-contained fixtures. ASCII-only to
# dodge Windows PowerShell 5.1 reading a BOM-less UTF-8 .ps1 as the ANSI codepage.
# Backup once per checksum mode, then byte-fraud the mid.bin RECORD block with
# rename / mtime / size / data attacks and see whether verify + restore react.
# Expectation: crc64 and sha256 both block all four (whole-volume pre-check now
# covers record metadata); none mostly does not (that is the old blind spot).
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_tamper_all'
if (Test-Path $VIN) { Remove-Item $VIN -Recurse -Force }
$SRC  = Join-Path $VIN 'src'; $WORK = Join-Path $VIN 'work'
New-Item -ItemType Directory -Force -Path $SRC, (Join-Path $SRC 'sub'), $WORK | Out-Null
Set-Content (Join-Path $SRC 'top.txt')     -Value ('head ' * 5000)       -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'sub\mid.bin') -Value ('mid data ' * 20000)  -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'tail.txt')    -Value ('tail ' * 3000)       -Encoding ascii -NoNewline

function Find-Rec($b, $startBlock) {
    for ($i = $startBlock; $i * 512 -lt $b.Length; $i++) {
        $p = $i * 512
        if ($p + 5 -lt $b.Length -and $b[$p] -eq 0x31 -and $b[$p + 1] -eq 0x44 -and $b[$p + 2] -eq 0x48 -and $b[$p + 3] -eq 0x52) {
            if ([Text.Encoding]::ASCII.GetString($b, $p + 114, 7) -match 'mid') { return $p }
        }
    }
    return -1
}

foreach ($cs in @('none', 'crc64', 'sha256')) {
    $arc = Join-Path $WORK ("$cs.dbkp")
    & $BK backup $SRC $arc -a none --checksum $cs 2>&1 | Out-Null
    $by = [IO.File]::ReadAllBytes($arc)
    $hdrSize = [BitConverter]::ToUInt16($by, 6)
    $startBlock = [int]($hdrSize / 512)
    $mid = Find-Rec $by $startBlock
    Write-Output ("===== checksum=$cs  headerSize=$hdrSize  midRec=$mid =====")
    & $BK verify $arc 2>&1 | Out-Null
    Write-Output ("  clean            verify rc=" + $LASTEXITCODE + " (expect 0)")

    function Attack($name, [scriptblock]$mutator) {
        $c = $by.Clone(); & $mutator $c $mid
        $t = Join-Path $WORK ("${cs}_$name.dbkp"); [IO.File]::WriteAllBytes($t, $c)
        & $BK verify $t 2>&1 | Out-Null; $vrc = $LASTEXITCODE
        $od = Join-Path $WORK "${cs}_$name.out"; if (Test-Path $od) { Remove-Item $od -Recurse -Force }
        $rr = & $BK restore $t $od '--force' 2>&1 | Out-String; $rrc = $LASTEXITCODE
        $err = (($rr -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)
        Write-Output ("  {0,-14} verify rc={1}  restore rc={2}  {3}" -f $name, $vrc, $rrc, $err)
    }
    Attack 'rename' { param($c, $m) $c[$m + 114 + 4] = [byte][char]'Z' }
    Attack 'mtime'  { param($c, $m) [BitConverter]::GetBytes([Int64]946684800).CopyTo($c, $m + 22) }
    Attack 'size'   { param($c, $m) [BitConverter]::GetBytes([Int64]1).CopyTo($c, $m + 86) }
    Attack 'data'   { param($c, $m) $c[$m + 600] = $c[$m + 600] -bxor 0xFF }
    Write-Output ''
}
Write-Output 'read: none rename/mtime expected UNDETECTED (no whole-volume digest); crc64 & sha256 must be rc!=0.'
