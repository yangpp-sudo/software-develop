# ============================================================================
#  e2e.ps1 -- end-to-end self test (Windows / MinGW build)
#  backup -> verify -> restore -> byte compare; all codecs; crypto; filters;
#  wrong-password rejection; tamper detection.
#  usage: powershell -ExecutionPolicy Bypass -File script/e2e.ps1
# ============================================================================
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$BK = ".\bin\bk.exe"
if (!(Test-Path $BK)) { Write-Host "build first: $BK not found"; exit 1 }

function New-Tree($p) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p }
    New-Item -ItemType Directory -Force -Path "$p/sub1/sub2" | Out-Null
    New-Item -ItemType Directory -Force -Path "$p/emptydir"  | Out-Null
    Set-Content -NoNewline -Encoding ascii "$p/a.txt"    ("hello dbkp " * 500)
    Set-Content -NoNewline -Encoding ascii "$p/b.log"    ("log line`n" * 300)
    Set-Content -NoNewline -Encoding ascii "$p/skip.tmp" "junk junk junk"
    Set-Content -NoNewline -Encoding ascii "$p/empty.txt" ""
    Set-Content -NoNewline -Encoding ascii "$p/sub1/sub2/deep.txt" "deep content"
    Set-Content -NoNewline -Encoding ascii "$p/sub1/$('x' * 200).txt" "long file name case"
    $rnd = New-Object byte[] 40000
    (New-Object Random).NextBytes($rnd)
    [IO.File]::WriteAllBytes("$p/sub1/rand.bin", $rnd)
}

function Get-TreeHash($p) {
    $base = (Resolve-Path $p).Path.Length + 1
    $map = @{}
    Get-ChildItem -Recurse -File $p | ForEach-Object {
        $map[$_.FullName.Substring($base).Replace('\', '/')] = (Get-FileHash $_.FullName -Algorithm SHA1).Hash
    }
    $dirs = @()
    Get-ChildItem -Recurse -Directory $p | ForEach-Object {
        $dirs += $_.FullName.Substring($base).Replace('\', '/')
    }
    return @{ files = $map; dirs = ($dirs | Sort-Object) }
}

$script:pass = 0
$script:fail = 0

function Case($name, $backupArgs, $restoreArgs, $verifyArgs, $allowMissing) {
    Write-Host ("=== " + $name + " ===")
    New-Tree "tsrc"
    if (Test-Path "tout") { Remove-Item -Recurse -Force "tout" }
    & $BK backup tsrc out.dbkp @backupArgs -q
    if ($LASTEXITCODE -ne 0) { Write-Host ("  FAIL backup rc=" + $LASTEXITCODE); $script:fail++; return }
    & $BK verify out.dbkp @verifyArgs -q
    if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL verify"; $script:fail++; return }
    & $BK restore out.dbkp tout --force @restoreArgs -q
    if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL restore"; $script:fail++; return }
    & $BK compare out.dbkp tsrc @verifyArgs -q
    if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL compare"; $script:fail++; return }
    $a = Get-TreeHash "tsrc"
    $b = Get-TreeHash "tout"
    $missA = @($a.files.Keys | Where-Object { -not $b.files.ContainsKey($_) })
    $missB = @($b.files.Keys | Where-Object { -not $a.files.ContainsKey($_) })
    $diff  = @($a.files.Keys | Where-Object { $b.files.ContainsKey($_) -and $a.files[$_] -ne $b.files[$_] })
    $bad = $missB.Count + $diff.Count
    if (-not $allowMissing) { $bad += $missA.Count }
    foreach ($d in $a.dirs) { if ($b.dirs -notcontains $d) { if (-not $allowMissing) { $bad++ } } }
    if ($bad -eq 0) {
        $info = ((& $BK info out.dbkp) | Select-String 'bytes|compression')
        Write-Host ("  PASS  src-files=" + $a.files.Count + " restored=" + $b.files.Count)
        Write-Host ("  " + ($info -join ' | '))
        $script:pass++
    } else {
        Write-Host ("  FAIL missing=" + ($missA -join ',') + " extra=" + ($missB -join ',') +
                   " contentdiff=" + ($diff -join ','))
        $script:fail++
    }
}

Case "plain backup/restore"  @() @() @() $false
Case "huffman"               @("-a","huffman") @() @() $false
Case "lz77"                  @("-a","lz77")    @() @() $false
Case "lzhuff (lz77+huffman)" @("-a","lzhuff")  @() @() $false
Case "rle"                   @("-a","rle")     @() @() $false
Case "aes256-cbc + huffman"  @("-a","huffman","-c","aes256","-p","S3cret!") @("-p","S3cret!") @("-p","S3cret!") $false
Case "chacha20 + lz77"       @("-a","lz77","-c","chacha20","-p","S3cret!")  @("-p","S3cret!") @("-p","S3cret!") $false
Case "filter: exclude *.tmp" @("--no-name","*.tmp") @() @() $true
Case "filter: only *.txt"    @("--name","*.txt")    @() @() $true
Case "filter: max-depth 1"   @("--max-depth","1")   @() @() $true
Case "filter: min-size 1KB"  @("--min-size","1KB")  @() @() $true
Case "filter: type deny dir" @("--type","-D")       @() @() $true

Write-Host "=== copy mode (dir -> dir) with post CRC verify ==="
New-Tree "tsrc"
if (Test-Path "tcopy") { Remove-Item -Recurse -Force "tcopy" }
& $BK backup tsrc tcopy --copy -q
if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL copy backup"; $script:fail++ }
else {
    $a = Get-TreeHash "tsrc"; $b = Get-TreeHash "tcopy"
    $missA = @($a.files.Keys | Where-Object { -not $b.files.ContainsKey($_) })
    $diff  = @($a.files.Keys | Where-Object { $b.files.ContainsKey($_) -and $a.files[$_] -ne $b.files[$_] })
    if (($missA.Count + $diff.Count) -eq 0) { Write-Host ("  PASS copied " + $b.files.Count + " files"); $script:pass++ }
    else { Write-Host ("  FAIL missing=" + ($missA -join ',') + " diff=" + ($diff -join ',')); $script:fail++ }
}

Write-Host "=== restore from a copied backup dir ==="
if (Test-Path "tcopy2") { Remove-Item -Recurse -Force "tcopy2" }
& $BK restore tcopy tcopy2 --force -q
if ($LASTEXITCODE -ne 0) { Write-Host ("  FAIL restore-copy rc=" + $LASTEXITCODE); $script:fail++ }
else {
    $a = Get-TreeHash "tsrc"; $b = Get-TreeHash "tcopy2"
    $missA = @($a.files.Keys | Where-Object { -not $b.files.ContainsKey($_) })
    $diff  = @($a.files.Keys | Where-Object { $b.files.ContainsKey($_) -and $a.files[$_] -ne $b.files[$_] })
    if (($missA.Count + $diff.Count) -eq 0) { Write-Host "  PASS round-trip via copy dir"; $script:pass++ }
    else { Write-Host ("  FAIL missing=" + ($missA -join ',') + " diff=" + ($diff -join ',')); $script:fail++ }
}

Write-Host "=== schedule: 3 runs every 1s, keep only 2 ==="
if (Test-Path "tsched") { Remove-Item -Recurse -Force "tsched" }
& $BK schedule tsrc tsched --every 1s --times 3 --keep 2 -a huffman -q
$kept = @(Get-ChildItem -File tsched -Filter *.dbkp -ErrorAction SilentlyContinue)
if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL schedule rc"; $script:fail++ }
elseif ($kept.Count -ne 2) { Write-Host ("  FAIL retention, archives=" + $kept.Count); $script:fail++ }
else {
    $bad = 0
    foreach ($k in $kept) { & $BK verify ("tsched\" + $k.Name) -q; if ($LASTEXITCODE -ne 0) { $bad++ } }
    if ($bad -eq 0) { Write-Host "  PASS retention + all kept archives verify"; $script:pass++ }
    else { Write-Host ("  FAIL " + $bad + " kept archives are broken"); $script:fail++ }
}

Write-Host "=== wrong password rejection ==="
New-Tree "tsrc"
& $BK backup tsrc out.dbkp -c aes256 -p rightpass -q | Out-Null
if (Test-Path "tout") { Remove-Item -Recurse -Force "tout" }
& $BK restore out.dbkp tout --force -p wrongpass -q 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host ("  PASS rejected rc=" + $LASTEXITCODE); $script:pass++ }
else { Write-Host "  FAIL wrong password accepted"; $script:fail++ }

Write-Host "=== tampered archive detection ==="
$fs = [IO.File]::Open((Resolve-Path "out.dbkp"), 'Open', 'ReadWrite')
$fs.Seek(600, 'Begin') | Out-Null
$fs.WriteByte(0xFF)
$fs.Close()
& $BK verify out.dbkp -p rightpass -q 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host ("  PASS tamper detected rc=" + $LASTEXITCODE); $script:pass++ }
else { Write-Host "  FAIL tamper not detected"; $script:fail++ }

Write-Host ""
Write-Host ("TOTAL PASS=" + $script:pass + " FAIL=" + $script:fail)
if ($script:fail -eq 0) { exit 0 } else { exit 1 }
