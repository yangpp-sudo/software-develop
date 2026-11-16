# B6 真4GB / B8 深层嵌套 / C15 API并发 —— 结果全部落盘到 RESULT.txt
$ErrorActionPreference = "SilentlyContinue"
$root = "C:\Users\user\Desktop\develop\software-develop\dbkp"
$w    = "$root\_probe\challenge\heavy"
$bk   = "$root\bin\bk.exe"
$bkd  = "$root\bin\bkd.exe"
Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $w -Force | Out-Null
$R = @()

# ---------- B6: 4GB 稀疏单文件 round-trip ----------
$R += "==== B6: 4GB+ sparse single file ===="
New-Item -ItemType Directory -Path "$w\b6\src" -Force | Out-Null
$f = "$w\b6\src\huge.bin"
& fsutil file createnew "$f" 4294967297 2>&1 | Out-Null   # 4GB+1 (稀疏,不占实际磁盘)
$R += "created_size=$((Get-Item $f).Length)"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $bk -ArgumentList @("backup","$w\b6\src","$w\b6\box.dbkp","-a","none") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b6pack.txt" -RedirectStandardError "$w\b6packe.txt"
$sw.Stop()
$R += "pack_exit=$($p.ExitCode) elapsed_ms=$($sw.ElapsedMilliseconds)"
$R += (Get-Content "$w\b6pack.txt")
$R += (Get-Content "$w\b6packe.txt")
if ($p.ExitCode -eq 0) {
    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
    $p2 = Start-Process -FilePath $bk -ArgumentList @("restore","$w\b6\box.dbkp","$w\b6\out","-a","none") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b6rest.txt" -RedirectStandardError "$w\b6reste.txt"
    $sw2.Stop()
    $R += "restore_exit=$($p2.ExitCode) elapsed_ms=$($sw2.ElapsedMilliseconds)"
    $R += (Get-Content "$w\b6rest.txt")
    $R += (Get-Content "$w\b6reste.txt")
    $rf = "$w\b6\out\huge.bin"
    if (Test-Path $rf) { $R += "restored_size=$((Get-Item $rf).Length) (expect 4294967297)" }
    else { $R += "restored_size=MISSING" }
}

# ---------- B8: 深层嵌套目录(用长路径前缀创建) ----------
$R += ""
$R += "==== B8: deep nested dirs (stack overflow?) ===="
foreach ($depth in @(200, 1000)) {
    $base = "\\?\$root\_probe\challenge\heavy\b8\d$depth"
    # 逐级创建,每级名字 2 字符
    $cur = $base
    New-Item -ItemType Directory -Path $cur -Force | Out-Null
    for ($i=0; $i -lt $depth; $i++) {
        $cur = $cur + "\a"
        New-Item -ItemType Directory -Path $cur -Force | Out-Null
    }
    "x" | Set-Content "$cur\leaf.txt"
    $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
    $pd = Start-Process -FilePath $bk -ArgumentList @("backup","$w\b8\d$depth","$w\b8\box$depth.dbkp") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b8o$depth.txt" -RedirectStandardError "$w\b8e$depth.txt"
    $sw3.Stop()
    # 0xC00000FD = -1073741571 = 栈溢出
    $R += "depth=$depth exit=$($pd.ExitCode) elapsed_ms=$($sw3.ElapsedMilliseconds)"
    $R += (Get-Content "$w\b8o$depth.txt" | Select-Object -Last 3)
    $R += (Get-Content "$w\b8e$depth.txt" | Select-Object -Last 3)
}

# ---------- C15: API 并发(起 bkd, 发 200 个 restore) ----------
$R += ""
$R += "==== C15: bkd API 200 concurrent ===="
New-Item -ItemType Directory -Path "$w\c15\src" -Force | Out-Null
"data" | Set-Content "$w\c15\src\a.txt"
$p0 = Start-Process -FilePath $bk -ArgumentList @("backup","$w\c15\src","$w\c15\box.dbkp") -NoNewWindow -Wait -PassThru
$port = 18099
$srv = Start-Process -FilePath $bkd -ArgumentList @("--host","127.0.0.1","--port","$port","--data-root","$w\c15\data","--web","$root\web") -NoNewWindow -PassThru -RedirectStandardOutput "$w\c15srv.txt" -RedirectStandardError "$w\c15srve.txt"
Start-Sleep -Seconds 2
$alive = -not $srv.HasExited
$R += "bkd_started=$alive pid=$($srv.Id)"
if ($alive) {
    $ok=0; $fail=0
    $jobs = for($i=0;$i -lt 200;$i++){
        Start-Job -ScriptBlock {
            param($p,$box,$out)
            try {
                $body = @{type="restore";source=$box;target=$out} | ConvertTo-Json
                $r = Invoke-WebRequest -Uri "http://127.0.0.1:$p/api/task" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 20 -UseBasicParsing
                $r.StatusCode
            } catch { "ERR" }
        } -ArgumentList $port,"$w\c15\box.dbkp","$w\c15\out$i"
    }
    $res = $jobs | Wait-Job -Timeout 60 | Receive-Job
    foreach($x in $res){ if($x -eq 200 -or $x -eq 202){$ok++} else {$fail++} }
    $R += "http_2xx=$ok  other_or_err=$fail  (jobs=$($jobs.Count))"
    $R += "bkd_still_alive=$(-not $srv.HasExited)"
    Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
} else {
    $R += "bkd failed to start; stderr:"
    $R += (Get-Content "$w\c15srve.txt")
}

$R | Set-Content "$w\RESULT.txt"
