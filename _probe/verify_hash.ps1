# Independent round-trip proof: compare source tree vs restored tree with
# Get-FileHash SHA-256 (i.e. NOT trusting bk compare).
# Test-only; nothing in the project tree is touched.
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'hashsrc'
$WORK = Join-Path $VIN 'hashwork'
if (Test-Path $SRC)  { Remove-Item $SRC  -Recurse -Force }
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Force -Path $SRC, $WORK | Out-Null

# --- fixture: compressible text, incompressible random, empty, sparse-ish, CJK, deep
Set-Content (Join-Path $SRC 'text_a.txt')   -Value ('The quick brown fox. ' * 8000) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'text_b.md')    -Value ('# heading' + ("`n" + 'lorem ipsum dolor ' * 3000)) -Encoding ascii
Set-Content (Join-Path $SRC 'empty.dat')    -Value '' -Encoding ascii -NoNewline
$bin = New-Object byte[] 3000000
(New-Object Random 20261110).NextBytes($bin)
[IO.File]::WriteAllBytes((Join-Path $SRC 'rnd3m.bin'), $bin)
$two = New-Object byte[] 66000; for ($i = 0; $i -lt $two.Length; $i++) { $two[$i] = [byte]($i % 251) }
[IO.File]::WriteAllBytes((Join-Path $SRC 'pattern.bin'), $two)
New-Item -ItemType Directory -Force -Path (Join-Path $SRC 'sub\deep\er') | Out-Null
Set-Content (Join-Path $SRC 'sub\in.txt')   -Value ('nested payload ' * 1200) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'sub\deep\er\x.log') -Value ('x' * 45000) -Encoding ascii -NoNewline
[IO.File]::WriteAllText((Join-Path $SRC ([regex]::Unescape('\u4e2d\u6587\u8bf4\u660e.txt'))), 'CJK name body', (New-Object Text.UTF8Encoding($false)))
New-Item -ItemType Directory -Force -Path (Join-Path $SRC 'hl') | Out-Null
$hlBody = New-Object byte[] 400000; (New-Object Random 7).NextBytes($hlBody)
[IO.File]::WriteAllBytes((Join-Path $SRC 'hl\one.bin'), $hlBody)
cmd /c mklink /H (Join-Path $SRC 'hl\two.bin') (Join-Path $SRC 'hl\one.bin') | Out-Null
(Get-Item (Join-Path $SRC 'text_b.md')).LastWriteTime = (Get-Date).AddDays(-900).AddHours(-7)

# --- baseline map built by PowerShell itself
function Map($base) {
    $h = @{}
    Get-ChildItem $base -Recurse -Force | ForEach-Object {
        $rel = $_.FullName.Substring($base.Length).TrimStart('\', '/')
        if ($_.PSIsContainer) { $h[$rel] = 'DIR:' + $_.LastWriteTimeUtc.Ticks }
        else { $h[$rel] = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash + '|' + $_.Length + '|' + $_.LastWriteTimeUtc.Ticks }
    }
    return $h
}
$want = Map $SRC
Write-Output ("fixture: " + @($want.Keys | Where-Object { $want[$_] -notlike 'DIR:*' }).Count + " files, " +
              @($want.Keys | Where-Object { $want[$_] -like 'DIR:*' }).Count + " dirs, " +
              "{0:N0} bytes total" -f ((Get-ChildItem $SRC -Recurse -File | Measure-Object Length -Sum).Sum))
Write-Output ''
Write-Output '== SHA-256 (PowerShell-computed) round-trip proof, per compression x crypto combo =='

$algos  = @('none', 'huffman', 'lz77', 'lzhuff', 'rle')
$crypts = @('none', 'aes256', 'chacha20', 'xor')
$fails  = 0
foreach ($a in $algos) {
    foreach ($c in $crypts) {
        $tag = "$a+$c"
        $arc = Join-Path $WORK ("rt_$($tag -replace '[^a-z0-9]','_').dbkp")
        $dst = Join-Path $WORK ("rt_$($tag -replace '[^a-z0-9]','_').rest")
        $bw = @('backup', $SRC, $arc, '-a', $a)
        if ($c -ne 'none') { $bw += @('-c', $c, '-p', 'Hash-Proof-1') }
        $b = & $BK @bw 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Write-Output ("  {0,-20} BACKUP FAILED rc={1} {2}" -f $tag, $LASTEXITCODE, ($b -split "`r?`n" | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1)); $fails++; continue }
        $rw = @('restore', $arc, $dst, '--force')
        if ($c -ne 'none') { $rw += @('-p', 'Hash-Proof-1') }
        $r = & $BK @rw 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { Write-Output ("  {0,-20} RESTORE FAILED rc={1}" -f $tag, $LASTEXITCODE); $fails++; continue }
        $got = Map $dst
        $miss = @($want.Keys | Where-Object { -not $got.ContainsKey($_) })
        $extra = @($got.Keys | Where-Object { -not $want.ContainsKey($_) })
        $diff  = @($want.Keys | Where-Object { $got.ContainsKey($_) -and $got[$_] -ne $want[$_] })
        $contentDiff = @($diff | Where-Object { $want[$_] -notlike 'DIR:*' })
        $timeDiff    = @($diff | Where-Object { $want[$_] -like 'DIR:*' })
        $asz = (Get-Item $arc).Length
        $raw = (Get-ChildItem $SRC -Recurse -File | Measure-Object Length -Sum).Sum
        if ($miss.Count -eq 0 -and $extra.Count -eq 0 -and $contentDiff.Count -eq 0) {
            $note = ''
            if ($timeDiff.Count -gt 0) { $note = "  (timestamp drift on " + $timeDiff.Count + " dirs: " + ($timeDiff -join ',') + ")" }
            $nf = @($want.Keys | Where-Object { $want[$_] -notlike 'DIR:*' }).Count
            $nd = @($want.Keys | Where-Object { $want[$_] -like 'DIR:*' }).Count
            Write-Output ("  {0,-20} HASH-EXACT  {1} files + {2} dirs identical, {3:N0}B -> archive {4:N0}B ({5:N1}%){6}" -f $tag, `
                $nf, $nd, $raw, $asz, (100.0 * $asz / $raw), $note)
        } else {
            $fails++
            Write-Output ("  {0,-20} MISMATCH missing={1} extra={2} contentDiff={3} timeDiff={4}  [{5}]" -f $tag, `
                $miss.Count, $extra.Count, $contentDiff.Count, $timeDiff.Count, (($miss + $extra + $contentDiff + $timeDiff) | Select-Object -First 4) -join ',')
        }
    }
}
Write-Output ''
Write-Output ("HASH PROOF: combinations=20  failed=" + $fails)
