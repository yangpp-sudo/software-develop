# Fixture builder for manual feature verification.
# ASCII-only source: Windows PowerShell 5.1 reads BOM-less files as ANSI/GBK,
# so every CJK character is constructed from \uXXXX escapes instead.
$ErrorActionPreference = 'Stop'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$V    = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $V 'src'
$OUT  = Join-Path $V 'out'
if (Test-Path $V) { Remove-Item $V -Recurse -Force }
New-Item -ItemType Directory -Path $SRC, $OUT -Force | Out-Null

# CJK names via escapes
$zhFile  = [regex]::Unescape('\u4e2d\u6587\u8bf4\u660e.txt')         # zhong-wen-shuo-ming.txt
$zhBody  = [regex]::Unescape('\u4e2d\u6587\u8def\u5f84\u4e0e\u6587\u4ef6\u540d')
$longPre = [regex]::Unescape('\u957f\u8def\u5f84')                    # chang-lu-jing
$longFil = [regex]::Unescape('\u6df1\u4e00\u5c42\u6587\u4ef6')       # shen-yi-ceng-wen-jian

Set-Content -Path (Join-Path $SRC 'a.txt')     -Value ('hello dbkp ' * 2000) -Encoding ASCII -NoNewline
Set-Content -Path (Join-Path $SRC 'b.tmp')     -Value 'cache junk' -Encoding ASCII
New-Item -ItemType Directory -Path (Join-Path $SRC 'sub') -Force | Out-Null
Set-Content -Path (Join-Path $SRC 'sub\c.txt') -Value ('world ' * 3000) -Encoding ASCII -NoNewline
Set-Content -Path (Join-Path $SRC 'sub\d.log') -Value ('x' * 5000) -Encoding ASCII
New-Item -ItemType Directory -Path (Join-Path $SRC 'emptydir') -Force | Out-Null
Set-Content -Path (Join-Path $SRC 'zero.txt')  -Value '' -Encoding ASCII -NoNewline
Set-Content -Path (Join-Path $SRC $zhFile)     -Value $zhBody -Encoding UTF8
Set-Content -Path (Join-Path $SRC 'deep_small.txt') -Value 'tiny' -Encoding ASCII

# highly compressible payload
$pat = [Text.Encoding]::ASCII.GetBytes('ABCDEFGHIJ')
$buf = New-Object byte[] 200000
for ($i = 0; $i -lt $buf.Length; $i++) { $buf[$i] = $pat[$i % 10] }
[IO.File]::WriteAllBytes((Join-Path $SRC 'repeat.bin'), $buf)

# hard link (mklink /H needs no elevation on NTFS)
cmd /c mklink /H "$SRC\hard1.txt" "$SRC\sub\c.txt" | Out-Null

# very long path
$longDir = Join-Path $SRC ($longPre + ('abcdefgh' * 30))
New-Item -ItemType Directory -Path $longDir -Force | Out-Null
Set-Content -Path (Join-Path $longDir ($longFil + ('b' * 150) + '.txt')) -Value 'long path payload' -Encoding ASCII

Write-Host '== fixture overview =='
$f = Get-ChildItem $SRC -Recurse -File
$d = Get-ChildItem $SRC -Recurse -Directory
Write-Host ("  files={0} dirs={1} bytes={2}" -f $f.Count, $d.Count, (($f | Measure-Object Length -Sum).Sum))
$mx = $f | ForEach-Object { $_.FullName.Substring($SRC.Length + 1).Length } | Measure-Object -Maximum
Write-Host ("  max relpath len={0}" -f $mx.Maximum)
Write-Host ("  BK={0}" -f $BK)
Write-Host ("  V={0}" -f $V)
