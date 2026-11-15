# diskfull_test.ps1 -- Real disk-full test for bk.exe
# HOW TO RUN: open PowerShell AS ADMINISTRATOR, then:
#   powershell -ExecutionPolicy Bypass -File "C:\Users\user\Desktop\develop\software-develop\dbkp\script\diskfull_test.ps1"
# What it does (ONLY touches its own scratch dir + a 100MB virtual disk it creates):
#   1. create + attach a 100MB VHD mounted as drive X:
#   2. build 200MB of test data, pack it with bk.exe
#   3. restore into X:\t (disk will fill up mid-restore)
#   4. report: exit code / half-written files / leftover .tmp files
#   5. detach + delete the VHD (cleanup)
# No other system changes are made.

$ErrorActionPreference = "Continue"
$bk   = "C:\Users\user\Desktop\develop\software-develop\dbkp\bin\bk.exe"
$work = "C:\Users\user\Desktop\develop\_diskfull_test"
$vhd  = "$work\full100.vhd"
$letter = "X"

Write-Host "=== [0] admin check ==="
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "NOT running as admin - diskpart will fail. Right-click PowerShell -> Run as Administrator." -ForegroundColor Red
    exit 1
}

# detach leftover vhd from previous run (ignore errors)
if (Test-Path $vhd) {
    "@`nselect vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content "$work\detach.txt" -Encoding ASCII
    diskpart /s "$work\detach.txt" 2>$null | Out-Null
}
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Path $work | Out-Null

Write-Host "=== [1] create + attach 100MB VHD as ${letter}: ==="
@"
create vdisk file="$vhd" maximum=100 type=fixed
attach vdisk
list disk
"@ | Set-Content "$work\dp1.txt" -Encoding ASCII
diskpart /s "$work\dp1.txt" | Out-Null
Start-Sleep -Seconds 2

@"
select vdisk file=`"$vhd`"
create partition primary
format fs=ntfs quick
assign letter=$letter
"@ | Set-Content "$work\dp2.txt" -Encoding ASCII
diskpart /s "$work\dp2.txt"
Start-Sleep -Seconds 2

if (-not (Test-Path "${letter}:\")) {
    Write-Host "VHD attach failed - abort (no changes made to system)." -ForegroundColor Red
    exit 1
}
$free = (Get-PSDrive $letter).Free
Write-Host ("drive {0}: ready, free = {1} bytes" -f $letter, $free)

Write-Host "=== [2] build 200MB source + pack ==="
$src = "$work\src"
New-Item -ItemType Directory -Path $src | Out-Null
$chunk = New-Object byte[] (52428800)   # 50MB
for ($i = 1; $i -le 4; $i++) {
    (New-Object Random ($i * 7919)).NextBytes($chunk)
    [IO.File]::WriteAllBytes("$src\f$i.bin", $chunk)
}
& $bk backup $src "$work\box.dbkp"
Write-Host ("pack exit = " + $LASTEXITCODE)
if ($LASTEXITCODE -ne 0) { Write-Host "PACK FAILED - abort" -ForegroundColor Red; exit 1 }

Write-Host "=== [3] restore into ${letter}:\t (disk-full scenario) ==="
& $bk restore "$work\box.dbkp" "${letter}:\t"
$restoreExit = $LASTEXITCODE
Write-Host ("restore exit = " + $restoreExit + "   (expected: nonzero error, NOT silent success)")

Write-Host "=== [4] inspect drive ${letter}: ==="
$driveFree = (Get-PSDrive $letter).Free
Write-Host ("free space left = " + $driveFree)
$files = @(Get-ChildItem "${letter}:\t" -Recurse -ErrorAction SilentlyContinue)
Write-Host ("restored entries in X:\t = " + $files.Count)
$files | ForEach-Object { Write-Host ("    " + $_.FullName + "  size=" + $_.Length) }
$tmp = @(Get-ChildItem "${letter}:\" -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*.tmp" })
Write-Host ("leftover .tmp files = " + $tmp.Count)
$tmp | ForEach-Object { Write-Host ("    " + $_.FullName) }

Write-Host ""
Write-Host "=== VERDICT (fill in manually) ==="
Write-Host "- restore exit code nonzero?         (0 = BUG: silent partial success)"
Write-Host "- error message mentions disk full?  (says 'not empty' = N2-style wrong message)"
Write-Host "- half-written files in X:\t?        (count should be 0 or match warnings)"
Write-Host "- leftover .tmp files?               (should be 0)"

Write-Host "=== [5] cleanup: detach + delete VHD ==="
"@`nselect vdisk file=`"$vhd`"`ndetach vdisk" | Set-Content "$work\detach.txt" -Encoding ASCII
diskpart /s "$work\detach.txt" | Out-Null
Start-Sleep -Seconds 2
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host "done. scratch dir removed."
