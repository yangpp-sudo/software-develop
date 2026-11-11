# Web capability probe: does every API-supported option really take effect,
# and which of them has no control in web/index.html?
# Read-only for the project; all data lives under $env:TEMP\dbkp_verify\web.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ROOT = Split-Path $PSScriptRoot -Parent
$WEB  = Join-Path $ROOT 'dbkp\web'
$EXE  = Join-Path $ROOT 'dbkp\bin\bkd.exe'
$V    = Join-Path $env:TEMP 'dbkp_verify\web'
$SRC  = Join-Path $V 'src'
$PORT = 18095
$BASE = "http://127.0.0.1:$PORT"
$PASS = 'test123'
$token = ''

if (Test-Path $V) { Remove-Item $V -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $SRC 'sub'), (Join-Path $SRC 'deep\a\b\c'), (Join-Path $V 'out') | Out-Null
Set-Content (Join-Path $SRC 'big.txt')     -Value ('A' * 200000) -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'small.txt')   -Value 'tiny'          -Encoding ascii
Set-Content (Join-Path $SRC 'cache.tmp')   -Value ('C' * 50000)   -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'noext')       -Value ('N' * 50000)   -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'sub\s1.txt')  -Value ('S' * 50000)   -Encoding ascii -NoNewline
Set-Content (Join-Path $SRC 'deep\a\b\c\far.txt') -Value ('F' * 50000) -Encoding ascii -NoNewline
# one deliberately old file for mtime filters
(Get-Item (Join-Path $SRC 'small.txt')).LastWriteTime = (Get-Date).AddDays(-400)
# hardlink pair, so hardlinkDedupe has something to bite on
New-Item -ItemType Directory -Force -Path (Join-Path $SRC 'hl') | Out-Null
Set-Content (Join-Path $SRC 'hl/linkme.bin') -Value ('H' * 120000) -Encoding ascii -NoNewline
cmd /c mklink /H (Join-Path $SRC 'hl/linkme2.bin') (Join-Path $SRC 'hl/linkme.bin') | Out-Null

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
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $st = [int]$resp.StatusCode
        $rd = New-Object IO.StreamReader($resp.GetResponseStream())
        $txt = $rd.ReadToEnd()
        if (-not $txt -and $_.ErrorDetails -and $_.ErrorDetails.Message) { $txt = $_.ErrorDetails.Message }
    }
    $o = $null
    if ($txt -and $txt.TrimStart().StartsWith('{')) { try { $o = $txt | ConvertFrom-Json } catch { $o = $null } }
    return @{ status = $st; json = $o; text = $txt }
}

function Run-Job($bodyObj, $timeout = 100) {
    $r = Api POST '/api/jobs' $bodyObj
    if ($r.status -ne 201) { return @{ ok = $false; why = ("http " + $r.status + " " + $r.text) } }
    $id = $r.json.data.id
    for ($i = 0; $i -lt $timeout; $i++) {
        $g = Api GET "/api/jobs/$id" $null
        if ($g.json.data.state -in @('succeeded', 'failed', 'canceled')) {
            return @{ ok = ($g.json.data.state -eq 'succeeded'); id = $id; data = $g.json.data;
                      why = $g.json.data.message }
        }
        Start-Sleep -Milliseconds 100
    }
    return @{ ok = $false; why = 'timeout' }
}

Write-Output '== start bkd =='
$proc = Start-Process -FilePath $EXE -ArgumentList @(
    '--port', "$PORT", '--web', $WEB, '--data-root', $V,
    '--password', $PASS, '--log-level', 'info') -PassThru -WindowStyle Hidden `
    -RedirectStandardError (Join-Path $V 'bkd.err') -RedirectStandardOutput (Join-Path $V 'bkd.out')
Start-Sleep -Milliseconds 1500

try {
    $r = Api POST '/api/login' @{ password = $PASS }
    $token = $r.json.data.token
    Write-Output ("login: http=" + $r.status + " token=" + [bool]$token)

    $r = Api GET '/api/config' $null
    Write-Output '== /api/config keys =='
    Write-Output (($r.json.data.PSObject.Properties.Name | Sort-Object) -join ', ')
    Write-Output ("algorithms : " + ($r.json.data.algorithms -join ','))
    Write-Output ("crypto     : " + ($r.json.data.crypto -join ','))
    Write-Output ("checksum   : " + ($r.json.data.checksum -join ','))
    Write-Output ("full config json: " + $r.text)

    $srcU  = ($SRC  -replace '\\', '/')
    $baseB = @{ type = 'backup'; source = $srcU }

    Write-Output ''
    Write-Output '== baseline (no filter) =='
    $arc0 = ($V + '/out/base.dbkp') -replace '\\', '/'
    $b = Run-Job ($baseB + @{ destination = $arc0; algorithm = 'none'; crypto = 'none' })
    $E0 = $b.data.entriesDone
    Write-Output ("  baseline succeeded=" + $b.ok + " entriesDone=" + $E0 + " bytes=" + $b.data.bytesDone + " why=" + $b.why)

    Write-Output ''
    Write-Output '== every filter field the API accepts: does it really change the entry set? =='
    $fields = @(
        @{ n = 'filter.includePaths';  o = @{ includePaths  = @('sub/*') } },
        @{ n = 'filter.excludePaths';  o = @{ excludePaths  = @('big.txt') } },
        @{ n = 'filter.nameGlobs';     o = @{ nameGlobs     = @('*.txt') } },
        @{ n = 'filter.nameRejects';   o = @{ nameRejects   = @('*.tmp') } },
        @{ n = 'filter.typeAllow';     o = @{ typeAllow     = 'regular' } },
        @{ n = 'filter.typeDeny';      o = @{ typeDeny      = 'd' } },
        @{ n = 'filter.minSize';       o = @{ minSize       = '10KB' } },
        @{ n = 'filter.maxSize';       o = @{ maxSize       = '10KB' } },
        @{ n = 'filter.mtimeAfter';    o = @{ mtimeAfter    = '30d' } },
        @{ n = 'filter.mtimeBefore';   o = @{ mtimeBefore   = '30d' } },
        @{ n = 'filter.maxDepth';      o = @{ maxDepth      = 1 } },
        @{ n = 'filter.includeDirs=false'; o = @{ includeDirs = $false } },
        @{ n = 'filter.skipSpecials';  o = @{ skipSpecials  = $true } },
        @{ n = 'filter.followSymlinks';o = @{ followSymlinks = $true } }
    )
    foreach ($f in $fields) {
        $arc = ($V + '/out/' + ($f.n -replace '[^A-Za-z0-9]', '_') + '.dbkp') -replace '\\', '/'
        $res = Run-Job ($baseB + @{ destination = $arc; algorithm = 'none'; crypto = 'none'; filter = $f.o })
        $e = $res.data.entriesDone
        $delta = if ($res.ok) { [int]$e - [int]$E0 } else { 'N/A' }
        Write-Output ("  {0,-28} ok={1,-5} entries={2,-4} delta={3,-5} bytesDone={4}  {5}" -f $f.n, $res.ok, $e, $delta, $res.data.bytesDone, $res.why)
    }

    Write-Output ''
    Write-Output '== non-filter job options =='
    $cases = @(
        @{ n = 'comment';            o = @{ comment = 'probe-comment-123' } },
        @{ n = 'checksum=sha256';    o = @{ checksum = 'sha256' } },
        @{ n = 'checksum=none';      o = @{ checksum = 'none' } },
        @{ n = 'crypto=aes256';      o = @{ crypto = 'aes256'; password = 'pw1' } },
        @{ n = 'crypto=chacha20';    o = @{ crypto = 'chacha20'; password = 'pw1' } },
        @{ n = 'crypto=xor';         o = @{ crypto = 'xor'; password = 'pw1' } },
        @{ n = 'hardlinkDedupe=false'; o = @{ hardlinkDedupe = $false } },
        @{ n = 'preserveMeta=false'; o = @{ preserveMeta = $false } },
        @{ n = 'mode=copy';          o = @{ mode = 'copy'; destination = (($V + '/out/copydir') -replace '\\', '/') } },
        @{ n = 'algorithm=lzhuff';   o = @{ algorithm = 'lzhuff' } },
        @{ n = 'algorithm=rle';      o = @{ algorithm = 'rle' } },
        @{ n = 'filter.uid';         o = @{ filter = @{ uid = 1000 } } },
        @{ n = 'filter.owner';       o = @{ filter = @{ owner = 'NobodyAtAll' } } },
        @{ n = 'filter.maxDepth=0';  o = @{ filter = @{ maxDepth = 0 } } }
    )
    foreach ($c in $cases) {
        $arc = ($V + '/opt_' + ($c.n -replace '[^A-Za-z0-9]', '_') + '.dbkp') -replace '\\', '/'
        $body = @{ type = 'backup'; source = $srcU; algorithm = 'none' }
        foreach ($k in @($c.o.Keys)) { $body[$k] = $c.o[$k] }
        if (-not $body.ContainsKey('destination')) { $body['destination'] = $arc }
        $res = Run-Job $body
        $diskSize = ''
        if (Test-Path ($V + '/opt_' + ($c.n -replace '[^A-Za-z0-9]', '_') + '.dbkp')) {
            $diskSize = (Get-Item ($V + '/opt_' + ($c.n -replace '[^A-Za-z0-9]', '_') + '.dbkp')).Length
        }
        $st = Api GET ('/api/stat?path=' + [uri]::EscapeDataString($body['destination'])) $null
        Write-Output ("  {0,-22} ok={1,-5} entries={2,-4} archiveOnDisk={3,-9} stat: files={4} dirs={5} links={6} alg={7} crypto={8} crc={9} comment={10}  {11}" -f `
            $c.n, $res.ok, $res.data.entriesDone, $diskSize, $st.json.data.fileCount, $st.json.data.dirCount, $st.json.data.linkCount, $st.json.data.algorithm, $st.json.data.crypto, $st.json.data.payloadCrc, $st.json.data.comment, $res.why)
    }

    Write-Output ''
    Write-Output '== /api/stat full payload (what the page could show but may not) =='
    $r = Api GET ('/api/stat?path=' + [uri]::EscapeDataString((($V + '/opt_comment.dbkp') -replace '\\', '/'))) $null
    Write-Output $r.text

    Write-Output ''
    Write-Output '== job detail payload =='
    $r = Api GET "/api/jobs/$($b.id)`?log=1" $null
    Write-Output $r.text

    Write-Output ''
    Write-Output '== endpoints that do NOT exist (CLI-only features) =='
    foreach ($ep in @('/api/schedule', '/api/watch', '/api/compare', '/api/users', '/api/incremental')) {
        $r = Api POST $ep @{ source = $srcU }
        Write-Output ("  POST {0,-18} -> http {1}  {2}" -f $ep, $r.status, ($r.text -replace '\s+', ' ' ))
    }
} finally {
    try { Api POST '/api/shutdown' $null | Out-Null } catch { }
    Start-Sleep -Milliseconds 800
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Write-Output '== bkd stopped =='
}
