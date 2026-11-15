# A1: --keep / --prefix 穿越测试（全部在 _probe/challenge 沙箱内，不碰真实文件）
# 判据：诱饵文件必须完好，且程序应拒绝含 .. / 路径分隔符 / 绝对形态的 prefix
$ErrorActionPreference = "SilentlyContinue"
$root = "C:\Users\user\Desktop\develop\software-develop\dbkp"
$w    = "$root\_probe\challenge\a1"
$bk   = "$root\bin\bk.exe"

Remove-Item -Recurse -Force $w -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path "$w\src" -Force | Out-Null
New-Item -ItemType Directory -Path "$w\out" -Force | Out-Null
"SECRET-SRC" | Set-Content "$w\src\a.txt"

# 诱饵：out 的同级、上级各放一个"看起来像备份"的文件
"BAIT-TOP-MUST-SURVIVE"    | Set-Content "$w\BAIT-prefix-20260101-00000-000.dbkp"
"BAIT-PARENT-MUST-SURVIVE" | Set-Content "$root\_probe\challenge\BAIT-prefix-20260101-00000-000.dbkp"

$out = @()
$out += "=== A1: prefix 带 ..\ 的 schedule ==="
# --prefix 用反斜杠 ..\ 试图让 makeArchiveName 把箱子写到 out 外面
$p = Start-Process -FilePath $bk -ArgumentList @(
    "schedule", "$w\src", "$w\out",
    "--every","1s", "--times","2", "--keep","1",
    "--prefix", "..\..\BAIT-prefix"
) -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$w\stdout.txt" -RedirectStandardError "$w\stderr.txt"
$out += "schedule_exit=$($p.ExitCode)"
$out += "--- stdout ---"
$out += (Get-Content "$w\stdout.txt" -ErrorAction SilentlyContinue)
$out += "--- stderr ---"
$out += (Get-Content "$w\stderr.txt" -ErrorAction SilentlyContinue)

$out += ""
$out += "=== 落点检查 ==="
$out += "--- out/ 内文件 ---"
$out += (Get-ChildItem "$w\out" -File -ErrorAction SilentlyContinue | ForEach-Object { "  " + $_.Name })
$out += "--- a1/ 根下所有 .dbkp（看有没有写到 out 外）---"
$out += (Get-ChildItem "$w" -Recurse -File -Filter *.dbkp -ErrorAction SilentlyContinue | ForEach-Object { "  " + $_.FullName.Replace($root,"") })
$out += "--- 诱饵内容（应仍是原文）---"
$out += "  BAIT-TOP    = '" + (Get-Content "$w\BAIT-prefix-20260101-00000-000.dbkp" -Raw -ErrorAction SilentlyContinue).Trim() + "'"
$out += "  BAIT-PARENT = '" + (Get-Content "$root\_probe\challenge\BAIT-prefix-20260101-00000-000.dbkp" -Raw -ErrorAction SilentlyContinue).Trim() + "'"

$out | Set-Content "$w\RESULT.txt"
Get-Content "$w\RESULT.txt"
