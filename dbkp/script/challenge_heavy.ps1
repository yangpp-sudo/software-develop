# B6 4GB / B8 深层嵌套 / C15 bkd并发 —— 前台分段、结果落盘、自动清理
$ErrorActionPreference = "SilentlyContinue"
$root = "C:\Users\user\Desktop\develop\software-develop\dbkp"
$w    = "$root\_probe\challenge\heavy"
$bk   = "$root\bin\bk.exe"
$bkd  = "$root\bin\bkd.exe"
New-Item -ItemType Directory -Path $w -Force | Out-Null
$R = New-Object System.Collections.ArrayList
function Add($s){ [void]$R.Add($s) }

# ---------- B6: 4GB+ 稀疏单文件 (只测 pack 阶段，观察 readWhole 是否爆内存) ----------
Add "==== B6: 4GB+ sparse single file ===="
New-Item -ItemType Directory -Path "$w\b6\src" -Force | Out-Null
$f = "$w\b6\src\huge.bin"
& fsutil file createnew "$f" 4294967297 2>&1 | Out-Null
Add "created_size=$((Get-Item $f).Length) (sparse, 实际不占 4GB 磁盘)"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $bk -ArgumentList @("backup","$w\b6\src","$w\b6\box.dbkp","-a","none") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b6pack.txt" -RedirectStandardError "$w\b6packe.txt"
$sw.Stop()
Add "pack_exit=$($p.ExitCode) elapsed_ms=$($sw.ElapsedMilliseconds)"
Add ((Get-Content "$w\b6pack.txt") -join " | ")
Add ((Get-Content "$w\b6packe.txt") -join " | ")
if ($p.ExitCode -eq 0 -and (Test-Path "$w\b6\box.dbkp")) {
    $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
    $p2 = Start-Process -FilePath $bk -ArgumentList @("restore","$w\b6\box.dbkp","$w\b6\out") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b6rest.txt" -RedirectStandardError "$w\b6reste.txt"
    $sw2.Stop()
    Add "restore_exit=$($p2.ExitCode) elapsed_ms=$($sw2.ElapsedMilliseconds)"
    Add ((Get-Content "$w\b6rest.txt") -join " | ")
    Add ((Get-Content "$w\b6reste.txt") -join " | ")
    $rf = "$w\b6\out\huge.bin"
    if (Test-Path $rf) { Add "restored_size=$((Get-Item $rf).Length) (expect 4294967297)" }
    else { Add "restored_size=MISSING" }
}

# ---------- B8: 深层嵌套(用 .NET 长路径 API 创建与清理) ----------
Add ""
Add "==== B8: deep nested dirs (stack overflow?) ===="
foreach ($depth in @(200, 1000)) {
    $base = "\\?\$root\_probe\challenge\heavy\b8\d$depth"
    [System.IO.Directory]::CreateDirectory($base) | Out-Null
    $cur = $base
    for ($i=0; $i -lt $depth; $i++) {
        $cur = $cur + "\a"
        [System.IO.Directory]::CreateDirectory($cur) | Out-Null
    }
    [System.IO.File]::WriteAllText($cur + "\leaf.txt", "x")
    $sw3 = [System.Diagnostics.Stopwatch]::StartNew()
    $pd = Start-Process -FilePath $bk -ArgumentList @("backup","$w\b8\d$depth","$w\b8\box$depth.dbkp") -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\b8o$depth.txt" -RedirectStandardError "$w\b8e$depth.txt"
    $sw3.Stop()
    Add "depth=$depth exit=$($pd.ExitCode) elapsed_ms=$($sw3.ElapsedMilliseconds)"
    Add (("stdout: " + ((Get-Content "$w\b8o$depth.txt" | Select-Object -Last 2) -join " | ")))
    Add (("stderr: " + ((Get-Content "$w\b8e$depth.txt" | Select-Object -Last 2) -join " | ")))
    # 立即用长路径 API 清理，避免残留超长路径
    [System.IO.Directory]::Delete("\\?\$root\_probe\challenge\heavy\b8\d$depth", $true) 2>$null | Out-Null
}

# ---------- C15: bkd API 并发(20 个并发, 观察队列上限/崩溃) ----------
Add ""
Add "==== C15: bkd API concurrent ===="
New-Item -ItemType Directory -Path "$w\c15\src" -Force | Out-Null
"data" | Set-Content "$w\c15\src\a.txt"
$p0 = Start-Process -FilePath $bk -ArgumentList @("backup","$w\c15\src","$w\c15\box.dbkp") -NoNewWindow -Wait -PassThru
$port = 18099
$srv = Start-Process -FilePath $bkd -ArgumentList @("--host","127.0.0.1","--port","$port","--data-root","$w\c15\data","--web","$root\web") -NoNewWindow -PassThru -RedirectStandardOutput "$w\c15srv.txt" -RedirectStandardError "$w\c15srve.txt"
Start-Sleep -Seconds 2
$alive = -not $srv.HasExited
Add "bkd_started=$alive pid=$($srv.Id)"
if ($alive) {
    # 用 HttpClient 异步并发，避免 200 个 Start-Job 太重
    $clients = @()
    for($i=0;$i -lt 20;$i++){ $clients += [System.Net.Http.HttpClient]::new() }
    $tasks = @()
    for($i=0;$i -lt 20;$i++){
        $body = '{"type":"restore","source":"' + ("$w\c15\box.dbkp").Replace('\','\\') + '","target":"' + ("$w\c15\out$i").Replace('\','\\') + '"}'
        $content = New-Object System.Net.Http.StringContent($body, [System.Text.Encoding]::UTF8, "application/json")
        try { $tasks += $clients[$i].PostAsync("http://127.0.0.1:$port/api/task", $content) } catch {}
    }
    try { [System.Threading.Tasks.Task]::WaitAll($tasks, 30000) | Out-Null } catch {}
    $ok=0; $other=0
    foreach($t in $tasks){
        if($t.Status -eq 'RanToCompletion'){
            $code = [int]$t.Result.StatusCode
            if($code -ge 200 -and $code -lt 300){$ok++} else {$other++}
        } else { $other++ }
    }
    Add "http_2xx=$ok  other_or_faulted=$other  total=$($tasks.Count)"
    Add "bkd_still_alive=$(-not $srv.HasExited)"
    foreach($c in $clients){ $c.Dispose() }
    Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
} else {
    Add "bkd failed to start; stderr: " + ((Get-Content "$w\c15srve.txt") -join " | ")
}

$R | Set-Content "$w\RESULT.txt"
Get-Content "$w\RESULT.txt"
