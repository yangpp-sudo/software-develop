# Live check of the two surfaces the new UI depends on but earlier dumps skipped:
#   1) GET /api/stat?...&entries=1  -> checksum field + payloadDigest (sha256) + entries[]
#   2) GET /api/config              -> cryptos includes xor, filterFields includes includeDirs
# Self-contained: builds a sha256 archive with bk, serves it with bkd, then stops bkd.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$BKD  = Join-Path $ROOT 'dbkp\bin\bkd.exe'
$WEB  = Join-Path $ROOT 'dbkp\web'
$V    = Join-Path $env:TEMP 'dbkp_stat_live'
if (Test-Path $V) { Remove-Item $V -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $V 'src\a\b'), (Join-Path $V 'out') | Out-Null
Set-Content (Join-Path $V 'src\one.txt') -Value ('one ' * 300) -Encoding ascii -NoNewline
Set-Content (Join-Path $V 'src\a\two.txt') -Value ('two ' * 400) -Encoding ascii -NoNewline
Set-Content (Join-Path $V 'src\a\b\three.txt') -Value ('three ' * 500) -Encoding ascii -NoNewline
$arc = Join-Path $V 'out\live.dbkp'
& $BK backup (Join-Path $V 'src') $arc -a lz77 --checksum sha256 -q 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "backup failed rc=$LASTEXITCODE" }

$PORT = 18099
$BASE = "http://127.0.0.1:$PORT"
$PASS = 'livepw'
$p = Start-Process -FilePath $BKD -PassThru -WindowStyle Hidden `
     -ArgumentList @('--port', "$PORT", '--web', $WEB, '--data-root', $V, '--password', $PASS)
Start-Sleep -Seconds 1
try {
    $login = Invoke-RestMethod -Uri "$BASE/api/login" -Method Post -ContentType 'application/json' `
        -Body (@{ password = $PASS } | ConvertTo-Json)
    $H = @{ Authorization = 'Bearer ' + $login.data.token }

    Write-Output '== /api/config (cryptos + filterFields) =='
    $cfg = (Invoke-RestMethod -Uri "$BASE/api/config" -Headers $H).data
    $cryptoIds = @($cfg.cryptos | ForEach-Object { $_.id })
    Write-Output ('  cryptos       = ' + ($cryptoIds -join ','))
    Write-Output ('  xor present   = ' + ($cryptoIds -contains 'xor'))
    Write-Output ('  filterFields has includeDirs = ' + ($cfg.filterFields -match 'includeDirs'))
    Write-Output ('  checksums     = ' + ($cfg.checksums -join ','))

    Write-Output '== /api/stat?entries=1 (sha256 archive) =='
    $st = (Invoke-RestMethod -Uri "$BASE/api/stat?path=out/live.dbkp&entries=1" -Headers $H).data
    Write-Output ('  checksum      = ' + $st.checksum)
    Write-Output ('  headerSize    = ' + $st.headerSize)
    Write-Output ('  payloadDigest = ' + $st.payloadDigest + '  (len=' + ($st.payloadDigest.Length) + ')')
    Write-Output ('  entriesTotal  = ' + $st.entriesTotal + '  returned=' + @($st.entries).Count)
    $first = @($st.entries)[0]
    Write-Output ('  entry[0] keys = path/type/size/storedSize/mode/uid/gid/mtime/mtimeNs/nlink/algorithm/crypto/crc64')
    Write-Output ('  entry[0].path = ' + $first.path + '  size=' + $first.size + '  crc64=' + $first.crc64)

    Write-Output '== /api/compare (GET, archive vs origin) =='
    $cmp = (Invoke-RestMethod -Uri "$BASE/api/compare?archive=out/live.dbkp&origin=src" -Headers $H).data
    Write-Output ('  diffCount     = ' + $cmp.diffCount + '  (expect 0, intact archive vs its own source)')
} finally {
    Stop-Process -Id $p.Id -Force -EA SilentlyContinue
    Write-Output '== bkd stopped =='
}
