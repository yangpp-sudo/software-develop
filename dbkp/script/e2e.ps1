# ============================================================================
#  e2e.ps1 -- end-to-end self test (Windows / MinGW build)
#  backup -> verify -> restore -> byte compare; all codecs; crypto; filters;
#  metadata preservation; wrong-password rejection; tamper detection.
#  usage: powershell -ExecutionPolicy Bypass -File script/e2e.ps1 [-Keep]
#
#  踩过的两个坑，脚本里做了防护：
#   1) Set-Location 不改 .NET 进程当前目录 -> 混用 [IO.File]::xxx 会写到上层目录；
#   2) PowerShell 会把命令行里的 *.txt 按**当前目录**展开后再传给 exe（目录里没有
#      .txt 时原样传，有则展开成第一个匹配文件名），于是 "--name *.txt" 变成
#      "--name build_err.txt"，过滤用例退化成"0 条目也算 PASS"的空断言。
#      对策：固定工作目录为干净临时目录 + 通配模式一律用变量传 + 每个用例断言
#      归档条目数（见 Get-EntryCount）。
# ============================================================================
param([switch]$Keep)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$BK   = Join-Path $root "bin\bk.exe"
if (!(Test-Path $BK)) { Write-Host "build first: $BK not found"; exit 1 }

$work = Join-Path $env:TEMP ("dbkp_e2e_" + $PID)
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
[Environment]::CurrentDirectory = (Get-Location).Path
Write-Host ("run start: " + (Get-Date) + "  workdir: " + $work)
Start-Transcript -Path (Join-Path $root "e2e_run.log") -Force | Out-Null

$PAT_TXT = '*.txt'                 # 通配模式走变量，避免被 shell 展开
$PAT_TMP = '*.tmp'

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
    # .NET API 用绝对路径，避免进程当前目录与 PS 位置不一致
    $abs = [IO.Path]::Combine((Get-Location).Path, $p, "sub1", "rand.bin")
    [IO.File]::WriteAllBytes($abs, $rnd)
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

# bk info 的计数字段是 "content : N files, M dirs, ..."
function Get-EntryCount($archive, [bool]$wantDirs) {
    $line = (& $BK info $archive | Select-String 'content\s*:').Line
    if (-not $line) { return -1 }
    if ($line -match 'content\s*:\s*(\d+)\s*files,\s*(\d+)\s*dirs') {
        if ($wantDirs) { return [int]$Matches[2] } else { return [int]$Matches[1] }
    }
    return -1
}

$script:pass = 0
$script:fail = 0

function Case($name, $backupArgs, $restoreArgs, $verifyArgs, $allowMissing, $expectFiles) {
    Write-Host ("=== " + $name + " ===")
    New-Tree "tsrc"
    if (Test-Path "tout") { Remove-Item -Recurse -Force "tout" }
    & $BK backup tsrc out.dbkp @backupArgs -q
    if ($LASTEXITCODE -ne 0) { Write-Host ("  FAIL backup rc=" + $LASTEXITCODE); $script:fail++; return }
    # 先断言归档条目数：否则过滤用例可能"0 条目也算 PASS"（空断言）
    $script:lastArchiveFiles = Get-EntryCount "out.dbkp" $false
    if ($expectFiles -ge 0 -and $script:lastArchiveFiles -ne $expectFiles) {
        Write-Host ("  FAIL entry count: expected " + $expectFiles +
                    " files, archive has " + $script:lastArchiveFiles)
        $script:fail++; return
    }
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
        Write-Host ("  PASS  archive-files=" + $script:lastArchiveFiles +
                    " restored=" + $b.files.Count + " (src=" + $a.files.Count + ")")
        Write-Host ("  " + ($info -join ' | '))
        $script:pass++
    } else {
        Write-Host ("  FAIL missing=" + ($missA -join ',') + " extra=" + ($missB -join ',') +
                   " contentdiff=" + ($diff -join ','))
        $script:fail++
    }
}

# 每个用例都给定"归档里应有的文件数"，防止过滤失效/全被过滤也显示 PASS
Case "plain backup/restore"  @() @() @() $false 7
Case "huffman"               @("-a","huffman") @() @() $false 7
Case "lz77"                  @("-a","lz77")    @() @() $false 7
Case "lzhuff (lz77+huffman)" @("-a","lzhuff")  @() @() $false 7
Case "rle"                   @("-a","rle")     @() @() $false 7
Case "aes256-cbc + huffman"  @("-a","huffman","-c","aes256","-p","S3cret!") @("-p","S3cret!") @("-p","S3cret!") $false 7
Case "chacha20 + lz77"       @("-a","lz77","-c","chacha20","-p","S3cret!")  @("-p","S3cret!") @("-p","S3cret!") $false 7
Case "filter: exclude *.tmp" @("--no-name",$PAT_TMP) @() @() $true 6
Case "filter: only *.txt"    @("--name",$PAT_TXT)    @() @() $true 4
Case "filter: max-depth 1"   @("--max-depth","1")    @() @() $true 4
Case "filter: min-size 1KB"  @("--min-size","1KB")   @() @() $true 3
Case "filter: type deny dir" @("--type","-D")        @() @() $true 7

# --- 目录条目语义（改动过的行为，单独钉住） -------------------------------
Write-Host "=== filter: directory entry counts ==="
New-Tree "tsrc"
& $BK backup tsrc dc_plain.dbkp -q
& $BK backup tsrc dc_name.dbkp  --name $PAT_TXT -q
& $BK backup tsrc dc_depth.dbkp --max-depth 1 -q
& $BK backup tsrc dc_type.dbkp  --type -D -q
$checks = @(
    @{ n = "plain dirs (. + sub1 + sub1/sub2 + emptydir)"; got = Get-EntryCount "dc_plain.dbkp" $true; want = 4 },
    @{ n = "plain files";                                  got = Get-EntryCount "dc_plain.dbkp" $false; want = 7 },
    @{ n = "--name *.txt dirs (目录不匹配则不入档)";        got = Get-EntryCount "dc_name.dbkp" $true;  want = 0 },
    @{ n = "--max-depth 1 dirs (根+第1层目录)";             got = Get-EntryCount "dc_depth.dbkp" $true; want = 3 },
    @{ n = "--type -D dirs (显式拒绝目录)";                  got = Get-EntryCount "dc_type.dbkp"  $true; want = 0 }
)
$dirBad = 0
foreach ($c in $checks) {
    if ($c.got -ne $c.want) { Write-Host ("  FAIL " + $c.n + ": got " + $c.got + " want " + $c.want); $dirBad++ }
}
if ($dirBad -eq 0) { Write-Host ("  PASS all " + $checks.Count + " entry-count checks"); $script:pass++ }
else { $script:fail++ }

Write-Host "=== metadata: mtime of files AND directories survive the round trip ==="
New-Tree "tsrc"
# 给每个条目不同的时间戳；若目录元数据不是"先子后父"恢复，父目录时间会被顶掉
$t0 = [DateTime]'2021-03-04 05:06:07'
(Get-Item "tsrc/sub1/sub2").LastWriteTime = $t0.AddSeconds(120)
(Get-Item "tsrc/sub1").LastWriteTime      = $t0.AddSeconds(60)
(Get-Item "tsrc").LastWriteTime           = $t0
(Get-Item "tsrc/a.txt").LastWriteTime     = $t0.AddSeconds(180)
& $BK backup tsrc meta.dbkp -q
if ($LASTEXITCODE -ne 0) { Write-Host "  FAIL backup(meta)"; $script:fail++ }
else {
    if (Test-Path "tmout") { Remove-Item -Recurse -Force "tmout" }
    & $BK restore meta.dbkp tmout --force -q
    $pairs = @(
        @{ p = "tmout";            want = $t0 },
        @{ p = "tmout/sub1";       want = $t0.AddSeconds(60) },
        @{ p = "tmout/sub1/sub2";  want = $t0.AddSeconds(120) },
        @{ p = "tmout/a.txt";      want = $t0.AddSeconds(180) }
    )
    $mBad = 0
    foreach ($m in $pairs) {
        $item = Get-Item ($m.p -replace '/', '\')
        if ($item.LastWriteTime -ne $m.want) {
            Write-Host ("  FAIL mtime " + $m.p + ": got " + $item.LastWriteTime + " want " + $m.want); $mBad++
        }
    }
    # --no-meta 时不应该恢复时间
    if (Test-Path "tnmout") { Remove-Item -Recurse -Force "tnmout" }
    & $BK restore meta.dbkp tnmout --force --no-meta -q
    $nowItem = Get-Item "tnmout\a.txt"
    if ($nowItem.LastWriteTime -eq $t0.AddSeconds(180)) {
        Write-Host "  FAIL --no-meta still restored mtime"; $mBad++
    }
    if ($mBad -eq 0) { Write-Host "  PASS 4 timestamps restored + --no-meta honored"; $script:pass++ }
    else { $script:fail++ }
}

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
Write-Host ("run end: " + (Get-Date))
Set-Location $root
[Environment]::CurrentDirectory = (Get-Location).Path
if ($Keep) { Write-Host ("workdir kept: " + $work) }
else { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
Stop-Transcript | Out-Null
if ($script:fail -eq 0) { exit 0 } else { exit 1 }
