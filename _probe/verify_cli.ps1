# Manual feature verification against the grading rubric.
# Everything happens under $env:TEMP\dbkp_verify -- the project tree is untouched.
$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'src'
$WORK = Join-Path $VIN 'cli'
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Path $WORK | Out-Null
$script:pass = 0; $script:fail = 0
$script:LOG = Join-Path $VIN 'cli_raw.txt'
Set-Content -Path $script:LOG -Value '' -Encoding UTF8

function Bk {
    param([string[]]$Cmd)
    $o = & $BK @Cmd 2>&1 | Out-String
    $rc = $LASTEXITCODE
    Add-Content -Path $script:LOG -Value ("> bk " + ($Cmd -join ' ') + "`nrc=$rc`n" + $o.Trim() + "`n") -Encoding UTF8
    return @{ rc = $rc; out = $o }
}
function Ok   { param($n, $d) Write-Host ("  [PASS] {0}  {1}" -f $n, $d) -ForegroundColor Green; $script:pass++ }
function Bad { param($n, $d) Write-Host ("  [FAIL] {0}  {1}" -f $n, $d) -ForegroundColor Red;   $script:fail++ }
function Check { param($cond, $n, $d) if ($cond) { Ok $n $d } else { Bad $n $d } }
function Entries { param([string]$Arc, [string]$Pw)
    $a = @('info', $Arc); if ($Pw) { $a += @('-p', $Pw) }
    $r = Bk $a
    if ($r.out -match '(\d+)\s+files,\s*(\d+)\s+dirs') { return @([int]$Matches[1], [int]$Matches[2]) }
    return @(-1, -1)
}
function RoundTrip { param([string]$Name, [string]$ArcName, [array]$Extra, [string]$Pw)
    $arc = Join-Path $WORK $ArcName
    $res = Join-Path $WORK ($ArcName + '.rest')
    $bw = @('backup', $SRC, $arc) + $Extra
    if ($Pw) { $bw += @('-p', $Pw) }
    $b = Bk $bw
    if ($b.rc -ne 0) { Bad "$Name (backup)" ("rc=" + $b.rc + " " + ($b.out -replace '(?s).*?(\[ERROR\].*)', '$1').Trim()); return $null }
    $ra = @('restore', $arc, $res, '--force'); if ($Pw) { $ra += @('-p', $Pw) }
    $r = Bk $ra
    if ($r.rc -ne 0) { Bad "$Name (restore)" ("rc=" + $r.rc); return $null }
    $ca = @('compare', $arc, $SRC); if ($Pw) { $ca += @('-p', $Pw) }
    $c = Bk $ca
    if ($c.rc -ne 0) { Bad "$Name (compare)" ("rc=" + $c.rc + " " + $c.out.Trim()); return $null }
    $total = (Get-ChildItem $SRC -Recurse -File | Measure-Object Length -Sum).Sum
    Ok $Name ("{0}B -> {1}B ({2:N1}%), restore + byte-compare clean" -f $total, (Get-Item $arc).Length, (100.0 * (Get-Item $arc).Length / $total))
    return $arc
}

Write-Host '=== 1. built-in known-answer selftest (SHA/HMAC/PBKDF2/AES/ChaCha20/CRC64) ==='
$st = Bk @('selftest')
Check ($st.rc -eq 0 -and $st.out -notmatch 'FAIL') 'selftest' ('rc=' + $st.rc + '; ' + (($st.out -split "`r?`n" | Where-Object { $_ -match 'ok$|OK' }).Count) + ' 项 known-answer 全 ok')

Write-Host '=== 2. compression: 5 algorithms, size + byte-exact round trip ==='
foreach ($a in @('none', 'huffman', 'lz77', 'lzhuff', 'rle')) {
    RoundTrip -Name "compress=$a" -ArcName ("c_$a.dbkp") -Extra @('-a', $a) -Pw '' | Out-Null
}

Write-Host '=== 3. encryption: 3 algorithms, byte-exact round trip with password ==='
foreach ($cy in @('aes256', 'chacha20', 'xor')) {
    RoundTrip -Name "crypto=$cy" -ArcName ("e_$cy.dbkp") -Extra @('-a', 'huffman', '-c', $cy) -Pw 'S3cret-Pass' | Out-Null
}

Write-Host '=== 4. negative: wrong password must fail AND leave no output ==='
$wArc = Join-Path $WORK 'e_aes256.dbkp'
$wOut = Join-Path $WORK 'wp'
$wr = Bk @('restore', $wArc, $wOut, '--force', '-p', 'totally-wrong')
Check ($wr.rc -ne 0) 'wrong password rejected' ('rc=' + $wr.rc + '; msg=' + (($wr.out -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1) -join ''))
if (Test-Path $wOut) { Write-Host ('    NOTE: restore 失败仍然创建了输出目录 ' + $wOut + ' (内容=' + @(Get-ChildItem $wOut -Recurse -Force).Count + ' 项)') -ForegroundColor Yellow }

Write-Host '=== 5. negative: single-byte tamper must be caught with a real integrity error ==='
$tamperSrc = Join-Path $WORK 'c_huffman.dbkp'
if (Test-Path $tamperSrc) {
    $by = [IO.File]::ReadAllBytes($tamperSrc); $by[600] = $by[600] -bxor 0xFF
    $tf = Join-Path $WORK 'tampered.dbkp'; [IO.File]::WriteAllBytes($tf, $by)
    $t = Bk @('verify', $tf)
    Check ($t.rc -ne 0 -and $t.out -match 'crc|checksum|corrupt|damaged|truncat|mismatch|verify') 'tamper detected' ("rc=" + $t.rc + "; " + (($t.out -split "`r?`n" | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1) -join ''))
} else { Bad 'tamper detected' '没有可用于篡改的归档' }

Write-Host '=== 6. six filter dimensions (each must actually change the entry count) ==='
$bl = Entries (Join-Path $WORK 'c_none.dbkp') ''
Write-Host ("  baseline 未过滤 = {0} files / {1} dirs" -f $bl[0], $bl[1])
$fc = @(
    @{ a = @('--exclude', 'b.tmp');         want = 'less' },
    @{ a = @('--no-name', '*.tmp');         want = 'less' },
    @{ a = @('--name', '*.txt');            want = 'less' },
    @{ a = @('--include', 'sub');           want = 'less' },
    @{ a = @('--min-size', '100KB');        want = 'less' },
    @{ a = @('--max-size', '1KB');          want = 'less' },
    @{ a = @('--newer-than', '1h');         want = 'same' },
    @{ a = @('--older-than', '1h');         want = 'zero' },
    @{ a = @('--type', '-D');            want = 'nodir' },
    @{ a = @('--type', 'reg');           want = 'less' },
    @{ a = @('--type', 'file');          want = 'less' },
    @{ a = @('--type', 'F');             want = 'zero-F-is-FIFO' },
    @{ a = @('--max-depth', '1');           want = 'less' },
    @{ a = @('--uid', '0');                 want = 'same' },
    @{ a = @('--owner', [Environment]::UserName); want = 'same' }
)
foreach ($c in $fc) {
    $tag  = ($c.a -join '_').Replace('--', '').Replace('*', '')
    $fa   = Join-Path $WORK ("f_$tag.dbkp")
    $r    = Bk (@('backup', $SRC, $fa, '-a', 'none') + $c.a)
    $n    = Entries $fa ''
    $verdict = switch ($c.want) {
        'less' { $r.rc -eq 0 -and $n[0] -ge 0 -and $n[0] -lt $bl[0] }
        'zero' { $r.rc -eq 0 -and $n[0] -eq 0 }
        'same' { $r.rc -eq 0 -and $n[0] -eq $bl[0] }
        'nodir'{ $r.rc -eq 0 -and $n[1] -eq 0 -and $n[0] -eq $bl[0] }
        'zero-F-is-FIFO' { $r.rc -eq 0 -and $n[0] -eq 0 }
    }
    Check $verdict ("filter " + ($c.a -join ' ')) ("expect " + $c.want + " -> backup rc=" + $r.rc + ", got {0} files / {1} dirs" -f $n[0], $n[1])
}

Write-Host '=== 7. hardlink dedupe: storage + link relation restored ==='
$a1 = Join-Path $WORK 'hd_on.dbkp'; $a2 = Join-Path $WORK 'hd_off.dbkp'
Bk (@('backup', $SRC, $a1, '-a', 'none')) | Out-Null
Bk (@('backup', $SRC, $a2, '-a', 'none', '--no-hardlink')) | Out-Null
if (Test-Path $a1) {
    $s1 = (Get-Item $a1).Length; $s2 = (Get-Item $a2).Length
    Check ($s1 -lt $s2) 'hardlink dedupe saves space' ("去重=" + $s1 + "B  不去重=" + $s2 + "B")
    $hr = Bk @('restore', $a1, (Join-Path $WORK 'hd_rest'), '--force')
    $fs = Join-Path $WORK 'hd_rest\sub\c.txt'
    if ($hr.rc -eq 0 -and (Test-Path $fs)) {
        $nl = @(fsutil hardlink list $fs 2>&1 | Where-Object { $_ -match 'hd_rest' }).Count
        Check ($nl -ge 2) 'hardlink relation rebuilt after restore' ("还原后同一 inode 的链接数=" + $nl)
    } else { Bad 'hardlink relation rebuilt after restore' ("restore rc=" + $hr.rc) }
} else { Bad 'hardlink dedupe saves space' '备份失败' }

Write-Host '=== 8. metadata: file + directory timestamps preserved ==='
$mt = Bk @('restore', $a1, (Join-Path $WORK 'mt'), '--force')
if ($mt.rc -eq 0) {
    $s1f = Get-Item (Join-Path $SRC 'a.txt'); $d1f = Get-Item (Join-Path $WORK 'mt\a.txt')
    Check ($s1f.LastWriteTimeUtc -eq $d1f.LastWriteTimeUtc) 'file mtime preserved' ($s1f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss.fffffff') + ' == ' + $d1f.LastWriteTimeUtc.ToString('yyyy-MM-dd HH:mm:ss.fffffff'))
    $s1d = Get-Item (Join-Path $SRC 'sub'); $d1d = Get-Item (Join-Path $WORK 'mt\sub')
    Check ($s1d.LastWriteTimeUtc -eq $d1d.LastWriteTimeUtc) 'dir mtime preserved (逆序回填修复有效)' ($s1d.LastWriteTimeUtc.ToString('HH:mm:ss.fffffff') + ' == ' + $d1d.LastWriteTimeUtc.ToString('HH:mm:ss.fffffff'))
    $nm = Bk @('restore', $a1, (Join-Path $WORK 'mt_nometa'), '--force', '--no-meta')
    $dn = Get-Item (Join-Path $WORK 'mt_nometa\a.txt')
    Check ($nm.rc -eq 0 -and $dn.LastWriteTimeUtc -ne $s1f.LastWriteTimeUtc) '--no-meta really skips metadata' ('还原时间=' + $dn.LastWriteTimeUtc.ToString('HH:mm:ss'))
} else { Bad 'metadata checks' ("restore rc=" + $mt.rc) }

Write-Host '=== 9. very long path (403 chars) + CJK names ==='
$nAll = @(Get-ChildItem (Join-Path $WORK 'mt') -Recurse -File -ErrorAction SilentlyContinue)
$zh = [regex]::Unescape('\u4e2d\u6587\u8bf4\u660e.txt')
$deep = $nAll | Where-Object { $_.FullName.Length -gt 260 }
Check ($nAll.Count -eq 10 -and (Test-Path (Join-Path $WORK ('mt\' + $zh))) -and $deep.Count -ge 1) 'long path + CJK restored' ("文件=" + $nAll.Count + "/10, 中文文件存在=" + (Test-Path (Join-Path $WORK ('mt\' + $zh))) + ", 超 260 字符的文件=" + $deep.Count + " 个(最长全路径 " + (($deep | ForEach-Object { $_.FullName.Length } | Measure-Object -Maximum).Maximum) + " 字符)")
$li = Entries $a1 ''
Write-Host ("  归档条目：{0} files / {1} dirs（fixture 实为 10/3；403 字符相对路径走 'X' 扩展记录）" -f $li[0], $li[1])

Write-Host '=== 10. copy mode (dir -> dir) ==='
$cp = Bk (@('backup', $SRC, (Join-Path $WORK 'cpdir'), '--copy'))
$cr = Bk @('restore', (Join-Path $WORK 'cpdir'), (Join-Path $WORK 'cpdir2'))
$cn = @(Get-ChildItem (Join-Path $WORK 'cpdir') -Recurse -File -ErrorAction SilentlyContinue)
Check ($cp.rc -eq 0 -and $cr.rc -eq 0 -and $cn.Count -eq 10) 'copy mode backup + restore' ("rc=" + $cp.rc + "/" + $cr.rc + " 文件=" + $cn.Count + "/10")

Write-Host '=== 11. scheduled backup + retention (数据淘汰) ==='
$sd = Join-Path $WORK 'sched'
$sc = Bk @('schedule', $SRC, $sd, '--every', '1s', '--times', '3', '--keep', '2', '-a', 'none')
$kept = @(Get-ChildItem $sd -Filter '*.dbkp' -ErrorAction SilentlyContinue)
$allOk = ($kept.Count -gt 0); foreach ($k in $kept) { if ((Bk @('verify', $k.FullName)).rc -ne 0) { $allOk = $false } }
Check ($sc.rc -eq 0 -and $kept.Count -eq 2 -and $allOk) 'schedule --times 3 --keep 2' ("rc=" + $sc.rc + " 生成 3 份后保留 " + $kept.Count + " 份，保留份全部 verify 通过=" + $allOk)

Write-Host '=== 12. observation commands ==='
foreach ($cmdn in @('info', 'list', 'verify')) {
    $r = Bk @($cmdn, (Join-Path $WORK 'c_lzhuff.dbkp'))
    $line = (($r.out -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
    Check ($r.rc -eq 0 -and $r.out -match 'lzhuff|files|archive') ("bk $cmdn") ($line.Trim())
    if ($cmdn -eq 'list') { Write-Host ('    样例: ' + ((($r.out -split "`r?`n") | Where-Object { $_ -match 'sub|\.txt|\.bin' } | Select-Object -First 2) -join ' / ')) }
}

Write-Host '=== 13. archive comment (-m) stored and readable ==='
$cmt = [regex]::Unescape('\u5b9e\u9a8c\u9a8c\u6536\u5f52\u6863')
$cm = Bk (@('backup', $SRC, (Join-Path $WORK 'cmt.dbkp'), '-a', 'none', '-m', $cmt))
$ci = Bk @('info', (Join-Path $WORK 'cmt.dbkp'))
Check ($cm.rc -eq 0 -and $ci.out.Contains($cmt)) 'comment round-trip' ('info 输出含中文注释=' + $ci.out.Contains($cmt))

Write-Host '=== 14. checksum=sha256 path (Web API 有、CLI 无开关) ==='
$sh = Bk @('backup', $SRC, (Join-Path $WORK 'sha.dbkp'), '-a', 'none', '--checksum', 'sha256')
Check ($sh.rc -eq 0) 'CLI --checksum option exists' ('rc=' + $sh.rc + '; ' + (($sh.out -split "`r?`n" | Where-Object { $_ -match 'ERROR|unknown|invalid' } | Select-Object -First 1) -join ''))

Write-Host ''
Write-Host ("TOTAL PASS={0} FAIL={1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
