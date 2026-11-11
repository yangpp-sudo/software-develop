# Tamper matrix: flip one byte at a time in every structural region of a
# .dbkp archive and see whether bk verify / bk restore actually catch it.
# Also covers checksum=none / crc64 / sha256 archives (created through the
# Web API, because the CLI has no --checksum switch).
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$BKD  = Join-Path $ROOT 'dbkp\bin\bkd.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'tampsrc'
$WORK = Join-Path $VIN 'tampwork'
$PORT = 18097
$BASE = "http://127.0.0.1:$PORT"
$token = ''
if (Test-Path $SRC)  { Remove-Item $SRC  -Recurse -Force }
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $SRC 'sub'), $WORK | Out-Null
Set-Content (Join-Path $SRC 'small.txt') -Value ('small text ' * 200) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'sub\other.txt') -Value ('nested text ' * 1600) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'empty.dat') -Value '' -Encoding ascii -NoNewline
$b1 = New-Object byte[] 100000; (New-Object Random 11).NextBytes($b1)
[IO.File]::WriteAllBytes((Join-Path $SRC 'mid.bin'), $b1)

function Api($method, $path, $bodyObj) {
    $headers = @{}
    if ($token -ne '') { $headers['Authorization'] = "Bearer $token" }
    $p = @{ Uri = "$BASE$path"; Method = $method; Headers = $headers; UseBasicParsing = $true; TimeoutSec = 30 }
    if ($null -ne $bodyObj) {
        $p['ContentType'] = 'application/json; charset=utf-8'
        $p['Body'] = [Text.Encoding]::UTF8.GetBytes(($bodyObj | ConvertTo-Json -Depth 8 -Compress))
    }
    $st = 0; $txt = ''
    try { $r = Invoke-WebRequest @p; $st = [int]$r.StatusCode; $txt = $r.Content }
    catch {
        $resp = $_.Exception.Response; $st = [int]$resp.StatusCode
        $rd = New-Object IO.StreamReader($resp.GetResponseStream()); $txt = $rd.ReadToEnd()
        if (-not $txt -and $_.ErrorDetails -and $_.ErrorDetails.Message) { $txt = $_.ErrorDetails.Message }
    }
    $o = $null
    if ($txt -and $txt.TrimStart().StartsWith('{')) { try { $o = $txt | ConvertFrom-Json } catch { } }
    return @{ status = $st; json = $o; text = $txt }
}
function Wait-Job($id) {
    for ($i = 0; $i -lt 150; $i++) {
        $g = Api GET "/api/jobs/$id" $null
        if ($g.json.data.state -in @('succeeded', 'failed', 'canceled')) { return $g.json.data }
        Start-Sleep -Milliseconds 100
    }
    return @{ state = 'timeout' }
}

Write-Output '== build archives =='
$plain = Join-Path $WORK 'plain_none.dbkp'
& $BK backup $SRC $plain -a none 2>&1 | Out-Null
$lzh   = Join-Path $WORK 'plain_lzhuff.dbkp'
& $BK backup $SRC $lzh -a lzhuff 2>&1 | Out-Null
$aes   = Join-Path $WORK 'enc_aes.dbkp'
& $BK backup $SRC $aes -a none -c aes256 -p 'pw-tamp' 2>&1 | Out-Null

$proc = Start-Process -FilePath $BKD -ArgumentList @('--port', "$PORT", '--web', (Join-Path $ROOT 'dbkp\web'),
    '--data-root', $VIN, '--password', 't123', '--log-level', 'warn') -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $WORK 'bkd.err') -RedirectStandardOutput (Join-Path $WORK 'bkd.out')
Start-Sleep -Milliseconds 1500
$shaPath = ($VIN + '/tampwork/api_sha256.dbkp') -replace '\\', '/'
$nonPath = ($VIN + '/tampwork/api_none.dbkp')    -replace '\\', '/'
try {
    $token = (Api POST '/api/login' @{ password = 't123' }).json.data.token
    $srcU  = ($SRC -replace '\\', '/')
    foreach ($pair in @(@('sha256', $shaPath), @('none', $nonPath))) {
        $r = Api POST '/api/jobs' @{ type = 'backup'; source = $srcU; destination = $pair[1];
                                    algorithm = 'none'; crypto = 'none'; checksum = $pair[0] }
        $d = Wait-Job $r.json.data.id
        Write-Output ("  web checksum=" + $pair[0] + " -> " + $d.state)
    }
} finally {
    try { Api POST '/api/shutdown' $null | Out-Null } catch { }
    Start-Sleep -Milliseconds 600
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
}

# ---- locate structural offsets inside a pristine archive
function Find-Bytes($bytes, [byte[]]$pat, $from = 0) {
    for ($i = $from; $i -le $bytes.Length - $pat.Length; $i++) {
        $hit = $true
        for ($j = 0; $j -lt $pat.Length; $j++) { if ($bytes[$i + $j] -ne $pat[$j]) { $hit = $false; break } }
        if ($hit) { return $i }
    }
    return -1
}
function Offsets($path) {
    $by = [IO.File]::ReadAllBytes($path)
    $rec = Find-Bytes $by ([Text.Encoding]::ASCII.GetBytes('1DHR'))
    $list = @()
    $list += @{ n = 'archive-magic';   o = 1 }
    $list += @{ n = 'archive-version'; o = 4 }
    if ($rec -ge 0) {
        $list += @{ n = 'rec-flags';     o = $rec + 5 }
        $list += @{ n = 'rec-mtime';     o = $rec + 22 }
        $list += @{ n = 'rec-size';      o = $rec + 86 }
        $list += @{ n = 'rec-crc64';     o = $rec + 102 }
        $list += @{ n = 'rec-path';      o = $rec + 114 + 3 }
        # second record (usually the first real file) for data-area anchoring
        $rec2 = Find-Bytes $by ([Text.Encoding]::ASCII.GetBytes('1DHR')) ($rec + 8)
        $ext  = -1
        for ($i = 0; $i -lt [math]::Floor($by.Length / 512); $i++) {
            $p = $i * 512
            if ($p -lt $by.Length - 5 -and (Find-Bytes $by ([Text.Encoding]::ASCII.GetBytes('1DHR')) $p) -eq $p -and $by[$p + 4] -eq [byte][char]'X') { $ext = $p; break }
        }
        if ($ext -ge 0) { $list += @{ n = 'extend-record-path'; o = $ext + 114 + 3 } }
    }
    $list += @{ n = 'sweep-15pct'; o = [int]($by.Length * 0.15) }
    $list += @{ n = 'sweep-40pct'; o = [int]($by.Length * 0.40) }
    $list += @{ n = 'sweep-65pct'; o = [int]($by.Length * 0.65) }
    $list += @{ n = 'sweep-90pct'; o = [int]($by.Length * 0.90) }
    $list += @{ n = 'tail-16';     o = $by.Length - 16 }
    return @{ file = $by; list = $list; rec = $rec }
}

function Tamper-Case($label, $src, $mod, $pw) {
    $info = Offsets $src
    Write-Output ("--- " + $label + "  (size=" + $info.file.Length + ", firstRecord@" + $info.rec + ") ---")
    $undetected = 0
    foreach ($c in $info.list) {
        if ($c.o -lt 0 -or $c.o -ge $info.file.Length) { continue }
        $t = Join-Path $WORK ('t_' + ($c.n -replace '[^A-Za-z0-9]', '_') + '.dbkp')
        $by = $info.file.Clone()
        switch ($mod) {
            'flip' { $by[$c.o] = $by[$c.o] -bxor 0xFF }
            'zero' { $by[$c.o] = 0 }
        }
        [IO.File]::WriteAllBytes($t, $by)
        $v = & $BK verify $t 2>&1 | Out-String
        $vrc = $LASTEXITCODE
        $dst = Join-Path $WORK ('out_' + ($c.n -replace '[^A-Za-z0-9]', '_'))
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        $ra = @('restore', $t, $dst, '--force'); if ($pw) { $ra += @('-p', $pw) }
        $r = & $BK @ra 2>&1 | Out-String
        $rrc = $LASTEXITCODE
        $left = 0
        if (Test-Path $dst) { $left = @(Get-ChildItem $dst -Recurse -File -ErrorAction SilentlyContinue).Count }
        $msg = ((($v -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1) -join '') -replace '^.*\[ERROR\]', '[ERROR]'
        if ($vrc -ne 0 -and $rrc -ne 0) { $verdict = 'caught' } else { $verdict = 'SILENT'; $undetected++ }
        Write-Output ("  {0,-18} off={1,-8} verify rc={2} restore rc={3} filesWritten={4}  => {5}  {6}" -f `
            $c.n, $c.o, $vrc, $rrc, $left, $verdict, $msg.Trim())
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Remove-Item $t -Force -ErrorAction SilentlyContinue
    }
    Write-Output ("  undetected=" + $undetected)
}

Write-Output ''
Write-Output '== byte-flip matrix (algorithm=none keeps the layout predictable) =='
Tamper-Case 'crc64 archive, byte flipped' $plain 'flip' ''
Write-Output ''
Tamper-Case 'crc64 archive, byte zeroed'  $plain 'zero' ''
Write-Output ''
Tamper-Case 'sha256 archive (Web-created)' $shaPath 'flip' ''
Write-Output ''
Tamper-Case 'checksum=none archive (Web-created)' $nonPath 'flip' ''
Write-Output ''
Tamper-Case 'compressed lzhuff' $lzh 'flip' ''
Write-Output ''
Tamper-Case 'aes256 encrypted' $aes 'flip' 'pw-tamp'

Write-Output ''
Write-Output '== truncation / append =='
foreach ($m in @('cut-tail-512', 'cut-tail-4096', 'append-512', 'cut-middle-512')) {
    $by = [IO.File]::ReadAllBytes($plain)
    switch ($m) {
        'cut-tail-512'  { $nb = $by[0..($by.Length - 513)] }
        'cut-tail-4096' { $nb = $by[0..([math]::Max(0, $by.Length - 4097))] }
        'append-512'    { $nb = $by + (New-Object byte[] 512) }
        'cut-middle-512'{ $k = [int]($by.Length / 2); $nb = $by[0..($k - 1)] + $by[($k + 512)..($by.Length - 1)] }
    }
    $t = Join-Path $WORK ("tr_$m.dbkp"); [IO.File]::WriteAllBytes($t, [byte[]]$nb)
    $v = & $BK verify $t 2>&1 | Out-String; $vrc = $LASTEXITCODE
    $dst = Join-Path $WORK "tr_$m.out"; if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
    $r = & $BK restore $t $dst '--force' 2>&1 | Out-String; $rrc = $LASTEXITCODE
    $left = 0; if (Test-Path $dst) { $left = @(Get-ChildItem $dst -Recurse -File -ErrorAction SilentlyContinue).Count }
    $msg = ((($v -split "`r?`n") | Where-Object { $_ -match 'ERROR' } | Select-Object -First 1) -join '') -replace '^.*\[ERROR\]', '[ERROR]'
    Write-Output ("  {0,-16} orig={1,-8} new={2,-8} verify rc={3} restore rc={4} filesWritten={5}  {6}" -f $m, $by.Length, $nb.Length, $vrc, $rrc, $left, $msg.Trim())
}
