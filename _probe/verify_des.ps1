# ============================================================================
#  verify_des.ps1 -- DES-EDE-CBC(3DES) end-to-end evidence (ASCII only)
#  backup(-c des-ede) -> verify -> restore -> compare -> wrong-password reject
#  Run:  powershell -ExecutionPolicy Bypass -File _probe\verify_des.ps1
# ============================================================================
$ErrorActionPreference = 'SilentlyContinue'   # 成败全靠下面显式检查 $LASTEXITCODE / Test-Path，不让原生 stderr 中断脚本
$root = Split-Path -Parent $PSScriptRoot
$bk   = Join-Path $root 'dbkp\bin\bk.exe'
$work = Join-Path $root 'dbkp\tmp\des'
$pw   = 'S3cret-pass'

if (Test-Path $work) { Remove-Item -Recurse -Force $work }
$src  = Join-Path $work 'src'
$out  = Join-Path $work 'out'
$res  = Join-Path $work 'restore'
New-Item -ItemType Directory -Force -Path $src, $out, $res | Out-Null

# build a small but non-trivial tree (binary-ish + text + subfolder)
$bytes = 1..3000 | ForEach-Object { [byte](($_ * 37) -band 0xFF) }
[IO.File]::WriteAllBytes((Join-Path $src 'blob.bin'), $bytes)
Set-Content -Encoding ASCII -Path (Join-Path $src 'readme.txt') -Value ('hello des ' * 500)
New-Item -ItemType Directory -Force -Path (Join-Path $src 'sub') | Out-Null
Set-Content -Encoding ASCII -Path (Join-Path $src 'sub\note.txt') -Value 'nested content for 3DES'
$arc = Join-Path $out 'vol.dbkp'
$errLog = Join-Path $work 'bk.stderr.log'   # 故意失败步骤的 stderr 落文件，避免 2>&1 触发 NativeCommandError

$fails = @()
function Check($name, $cond) {
    if ($cond) { Write-Host ('  [OK]   ' + $name) }
    else       { Write-Host ('  [FAIL] ' + $name); $script:fails += $name }
}

Write-Host '== 1) backup with DES-EDE-CBC =='
& $bk backup $src $arc -c des-ede -a huffman -p $pw 2> $errLog | Out-Null
Check 'backup exit code == 0' ($LASTEXITCODE -eq 0)
Check 'archive exists'        (Test-Path $arc)

Write-Host '== 2) info shows crypto = des-ede-cbc =='
$info = & $bk info $arc -p $pw 2> $errLog | Out-String
Check 'info mentions des-ede-cbc' ($info -match 'des-ede')

Write-Host '== 3) verify =='
& $bk verify $arc -p $pw 2> $errLog | Out-Null
Check 'verify exit code == 0' ($LASTEXITCODE -eq 0)

Write-Host '== 4) restore =='
& $bk restore $arc $res -p $pw 2> $errLog | Out-Null
Check 'restore exit code == 0' ($LASTEXITCODE -eq 0)

Write-Host '== 5) byte-for-byte fidelity vs source =='
foreach ($f in @('blob.bin','readme.txt','sub\note.txt')) {
    $a = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $src $f)).Hash
    $b = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $res $f)).Hash
    Check ("identical: " + $f) ($a -eq $b)
}

Write-Host '== 6) compare archive vs source =='
& $bk compare $arc $src -p $pw 2> $errLog | Out-Null
Check 'compare exit code == 0' ($LASTEXITCODE -eq 0)

Write-Host '== 7) wrong password must be rejected =='
$bad = Join-Path $work 'restore_bad'
New-Item -ItemType Directory -Force -Path $bad | Out-Null
& $bk restore $arc $bad -p 'wrong-pass' 2> $errLog | Out-Null
Check 'wrong-password restore is non-zero' ($LASTEXITCODE -ne 0)

Write-Host '== 8) tamper ciphertext -> integrity check trips =='
$len = (Get-Item $arc).Length
$all = [IO.File]::ReadAllBytes($arc)
$mid = [int]($len * 0.6)                 # somewhere inside the encrypted payload
$all[$mid] = $all[$mid] -bxor 0xFF
[IO.File]::WriteAllBytes($arc, $all)
& $bk verify $arc -p $pw 2> $errLog | Out-Null
Check 'tampered archive verify is non-zero' ($LASTEXITCODE -ne 0)

Write-Host ''
if ($fails.Count -eq 0) { Write-Host 'DESEDE VERIFY OK'; exit 0 }
Write-Host ('DESEDE VERIFY FAILED: ' + ($fails -join '; ')); exit 1
