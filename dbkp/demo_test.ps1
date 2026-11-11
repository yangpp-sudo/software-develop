# demo_test.ps1 -- dbkp acceptance rehearsal (CLI only, no server, safe to run).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File .\demo_test.ps1
# It auto-locates bk.exe, so it can be placed in the dbkp root or in bin\.
$ErrorActionPreference = 'Continue'

$script:pass = 0
$script:fail = 0
$script:log  = @()

function Say($id, $name, $ok, $detail) {
  $tag = 'FAIL'
  if ($ok) { $tag = 'PASS'; $script:pass++ } else { $script:fail++ }
  $line = "{0,-4} {1,-38} [{2}] {3}" -f $id, $name, $tag, $detail
  Write-Host $line
  $script:log += $line
}

function FindBk {
  $cands = @(
    (Join-Path (Get-Location) 'bin\bk.exe'),
    (Join-Path (Get-Location) 'bk.exe'),
    (Join-Path (Get-Location) '..\bin\bk.exe'),
    'C:\Users\user\Desktop\develop\software-develop\dbkp\bin\bk.exe'
  )
  foreach ($c in $cands) { if (Test-Path $c) { return (Resolve-Path $c).Path } }
  return $null
}

function Run($exe, $arglist, $ms = 60000) {
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $exe
  $psi.Arguments = (($arglist | ForEach-Object { if ("$_" -match '\s') { '"' + $_ + '"' } else { "$_" } }) -join ' ')
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  $ot = $p.StandardOutput.ReadToEndAsync()
  $et = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($ms)) { try { $p.Kill() } catch {} ; return @{code = -88; out = ''; err = 'TIMEOUT/HANG'} }
  return @{code = $p.ExitCode; out = $ot.Result; err = $et.Result}
}

function HSha($p) { if (-not (Test-Path $p)) { return '' }; return (Get-FileHash $p -Algorithm SHA256).Hash }

Write-Host '=========================================='
Write-Host ' dbkp acceptance rehearsal'
Write-Host '=========================================='

# ---------- 0. locate binary ----------
$bk = FindBk
if (-not $bk) {
  Write-Host '[FATAL] bk.exe not found.'
  Write-Host '        Put this script in the dbkp root (the folder that contains bin, web, src).'
  Read-Host 'Press Enter to exit'
  exit 2
}
Write-Host ("bk.exe : {0}" -f $bk)
Write-Host ("workdir: will be created under current directory" -f 1)
Write-Host ''

# ---------- 1. prepare workdir ----------
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$work  = Join-Path (Get-Location) ("demo_work_" + $stamp)
$src   = Join-Path $work 'src'
$out   = Join-Path $work 'out'
New-Item -ItemType Directory -Force -Path $src, (Join-Path $src 'docs'), (Join-Path $src 'sub'), $out | Out-Null

# sample data: compressible text, random binary, empty file, nested file
Set-Content (Join-Path $src 'docs\readme.txt') (('dbkp acceptance sample line. ' * 400)) -Encoding ASCII
$rb = New-Object byte[] 65536
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($rb)
[IO.File]::WriteAllBytes((Join-Path $src 'data.bin'), $rb)
[IO.File]::WriteAllBytes((Join-Path $src 'empty.txt'), (New-Object byte[] 0))
Set-Content (Join-Path $src 'sub\note.txt') 'nested note' -Encoding ASCII

$hReadme = HSha (Join-Path $src 'docs\readme.txt')
$hData   = HSha (Join-Path $src 'data.bin')
$hNote   = HSha (Join-Path $src 'sub\note.txt')

# ---------- 2. tests ----------
$t = Run $bk @('selftest') 60000
Say 'T1' 'selftest' ($t.code -eq 0) ("exit={0}" -f $t.code)

$box = Join-Path $out 'box.dbkp'
$t = Run $bk @('backup', $src, $box) 120000
$made = Test-Path $box
Say 'T2' 'backup -> archive' (($t.code -eq 0) -and $made) ("exit={0} size={1}" -f $t.code, $(if ($made) { (Get-Item $box).Length } else { 0 }))

$t = Run $bk @('list', $box) 60000
$hasNames = ($t.out -match 'readme\.txt') -and ($t.out -match 'data\.bin') -and ($t.out -match 'note\.txt')
Say 'T3' 'list shows entries' (($t.code -eq 0) -and $hasNames) ("exit={0}" -f $t.code)

$t = Run $bk @('verify', $box) 120000
Say 'T4' 'verify archive' ($t.code -eq 0) ("exit={0}" -f $t.code)

$rd = Join-Path $out 'restored'
$t = Run $bk @('restore', $box, $rd) 120000
$okReadme = (HSha (Join-Path $rd 'docs\readme.txt')) -eq $hReadme
$okData   = (HSha (Join-Path $rd 'data.bin')) -eq $hData
$okNote   = (HSha (Join-Path $rd 'sub\note.txt')) -eq $hNote
$okEmpty  = Test-Path (Join-Path $rd 'empty.txt')
Say 'T5' 'restore + sha256 match' (($t.code -eq 0) -and $okReadme -and $okData -and $okNote -and $okEmpty) ("exit={0} readme={1} data={2} note={3} empty={4}" -f $t.code, $okReadme, $okData, $okNote, $okEmpty)

$t = Run $bk @('compare', $box, $src) 120000
Say 'T6' 'compare box vs source' ($t.code -eq 0) ("exit={0}" -f $t.code)

# encrypted roundtrip: wrong password must fail, right password must work
$enc = Join-Path $out 'enc.dbkp'
$t1 = Run $bk @('backup', $src, $enc, '-a', 'lzhuff', '-c', 'aes256', '-p', 's3cret') 120000
$rdw = Join-Path $out 'enc_bad'
$t2 = Run $bk @('restore', $enc, $rdw, '-p', 'WRONG') 120000
$rdg = Join-Path $out 'enc_good'
$t3 = Run $bk @('restore', $enc, $rdg, '-p', 's3cret') 120000
$okGood = (HSha (Join-Path $rdg 'data.bin')) -eq $hData
Say 'T7' 'encrypted wrong/right pw' (($t1.code -eq 0) -and ($t2.code -ne 0) -and ($t3.code -eq 0) -and $okGood) ("bk={0} wrongpw_exit={1} rightpw_exit={2} data_ok={3}" -f $t1.code, $t2.code, $t3.code, $okGood)

# tamper detection: flip one byte in the payload, verify must fail
$tam = Join-Path $out 'tampered.dbkp'
Copy-Item $box $tam -Force
$bytes = [IO.File]::ReadAllBytes($tam)
$mid = [int]($bytes.Length / 2)
$bytes[$mid] = $bytes[$mid] -bxor 0xFF
[IO.File]::WriteAllBytes($tam, $bytes)
$t = Run $bk @('verify', $tam) 120000
Say 'T8' 'tampered box detected' ($t.code -ne 0) ("exit={0} (expect != 0)" -f $t.code)

# directory copy mode (destination without .dbkp)
$cp = Join-Path $out 'copydir'
$t = Run $bk @('backup', $src, $cp) 120000
$okCopy = (HSha (Join-Path $cp 'data.bin')) -eq $hData
Say 'T9' 'plain dir copy mode' (($t.code -eq 0) -and $okCopy) ("exit={0} data_ok={1}" -f $t.code, $okCopy)

# ---------- 3. summary ----------
Write-Host ''
Write-Host '=========================================='
$total = $script:pass + $script:fail
Write-Host (" RESULT: {0}/{1} passed, {2} failed" -f $script:pass, $total, $script:fail)
Write-Host (" workdir: {0}" -f $work)
Write-Host '=========================================='

$logPath = Join-Path (Get-Location) ('demo_test_log_' + $stamp + '.txt')
Set-Content $logPath $script:log -Encoding ASCII
Write-Host (" log saved: {0}" -f $logPath)

if ($script:fail -eq 0) { exit 0 } else { exit 1 }
