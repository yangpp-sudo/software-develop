<#
.SYNOPSIS
    批次10 任务D：覆盖率收集（gcov + gcovr）。
.DESCRIPTION
    前置：构建并运行插桩测试（Makefile 的 coverage 目标负责）：
        mingw32-make OBJ=objcov OPT="-O0 -g --coverage" test
    本脚本做三件事：
      1) 在仓库根跑 gcov，把逐源文件的 .gcov 文本报告归档到 doc/perf/coverage/
      2) 用 gcovr 生成 HTML 报告 doc/perf/coverage_html/ + 汇总表 + XML
      3) 打印批次10 指定的核心文件语句覆盖率，逐个与 80% 红线对比
    环境坑（已实测）：
      - 本机 gcovr 固定 5.0（Python 3.6.4 下可装的版本）；
      - gcovr 的 -j 是"并行任务数"，不是对象目录，原脚本传 '-j objcov' 是错的；
      - gcov 必须在仓库根执行，*.gcov 才会落在可预测位置（在子目录跑会散在各处）。
#>
[CmdletBinding()]
param(
    [string] $Root = '',
    [string] $ObjDir = 'objcov',
    [string[]] $Targets = @(
        'src/Pack/MyPack.cpp',
        'src/Common/Serialize.cpp',
        'src/Enumerator/FilterOptions.cpp',
        'src/Codec/Huffman.cpp',
        'src/Codec/LZ77.cpp',
        'src/Codec/BitIo.cpp',
        'src/Codec/CodecFactory.cpp',
        'src/Crypto/Aes.cpp',
        'src/Crypto/ChaCha20.cpp',
        'src/Crypto/CryptoCodecs.cpp',
        'src/Crypto/Des.cpp',
        'src/Crypto/Sha256.cpp',
        'src/Utils/CRC64.cpp',
        'src/Utils/PathUtil.cpp',
        'src/Utils/SimpleFile.cpp'
    )
)

$ErrorActionPreference = 'Stop'
if (-not $Root) {
    $self = $MyInvocation.MyCommand.Path
    if (-not $self) { $self = (Resolve-Path (Join-Path (Get-Location) 'script/coverage_run.ps1')).Path }
    $Root = Split-Path -Parent (Split-Path -Parent $self)
}
Set-Location $Root

$outDir  = Join-Path $Root 'doc/perf/coverage'
$htmlDir = Join-Path $Root 'doc/perf/coverage_html'
New-Item -ItemType Directory -Force -Path $outDir  | Out-Null
New-Item -ItemType Directory -Force -Path $htmlDir | Out-Null

if (-not (Test-Path (Join-Path $Root $ObjDir))) {
    throw "对象目录 $ObjDir 不存在，请先执行 make coverage（或手工插桩构建）。"
}

# ---- 1. gcov 逐文件文本报告 --------------------------------------------------
Write-Host '==== [1/3] gcov 文本报告 ====' -ForegroundColor Cyan
# 清掉上一轮残留，避免把旧数据当成本轮结果
Get-ChildItem -Path $Root -Filter '*.gcov' -File -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -Path $outDir -Filter '*.gcov' -File -ErrorAction SilentlyContinue | Remove-Item -Force

$gcnoFiles = Get-ChildItem -Recurse -Path $ObjDir -Filter '*.gcno' | Sort-Object FullName
$gcovOk = 0
foreach ($f in $gcnoFiles) {
    # $f.DirectoryName 已经是字符串，不能再 .FullName（那样 -o 收到空值，gcov 直接报 usage）
    & gcov -b -c -o $f.DirectoryName $f.FullName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { $gcovOk++ }
}
# gcov 把 *.gcov 写在当前目录（仓库根）；按 .gcno 的相对子目录加前缀归档，
# 防止不同子目录里的同名源文件（如 Http.cpp / Api.cpp）互相覆盖。
$prefix = (Join-Path $Root $ObjDir) + '\'
# 只归档项目源文件的报告；gcov 顺带生成的 STL 头文件报告（stl_*.gcov 等）不入库
Get-ChildItem -Path $Root -Filter '*.cpp.gcov' -File | ForEach-Object {
    $src   = $_.Name -replace '\.gcov$', ''
    $match = $gcnoFiles | Where-Object { $_.BaseName -eq $src } | Select-Object -First 1
    $rel = ''
    if ($match) {
        $rel = $match.DirectoryName.Replace($prefix, '') -replace '\\', '_'
        if ($rel) { $rel += '_' }
    }
    Copy-Item $_.FullName (Join-Path $outDir ($rel + $_.Name)) -Force
    Remove-Item $_.FullName -Force
}
Get-ChildItem -Path $Root -Filter '*.gcov' -File | Remove-Item -Force
Write-Host ("  gcno {0} 个，gcov 成功 {1} 个，归档 .gcov {2} 份 -> {3}" -f `
    $gcnoFiles.Count, $gcovOk, (Get-ChildItem $outDir -Filter '*.gcov').Count, $outDir)

# ---- 2. gcovr 汇总（表格 + HTML + XML）--------------------------------------
Write-Host '==== [2/3] gcovr 表格 + HTML ====' -ForegroundColor Cyan
$baseArgs = @('--root', '.', '--filter', 'src/', '--exclude', 'test/', '--gcov-executable', 'gcov')
$table = & gcovr @baseArgs --print-summary 2>&1
$table | ForEach-Object { Write-Host $_ }
$table | Out-File -Encoding utf8 (Join-Path $outDir 'gcovr_table.txt')

& gcovr @baseArgs --html-details (Join-Path $htmlDir 'index.html') 2>&1 | Out-Null
& gcovr @baseArgs --xml (Join-Path $outDir 'coverage.xml') 2>&1 | Out-Null
Write-Host ("  HTML 报告 -> {0}" -f $htmlDir)

# ---- 3. 核心文件达标判定 ----------------------------------------------------
Write-Host '==== [3/3] 批次10 核心文件语句覆盖率 vs 80% 红线 ====' -ForegroundColor Cyan
$hit = 0
foreach ($t in $Targets) {
    $line = $table | Where-Object { $_ -match [regex]::Escape($t) } | Select-Object -First 1
    if (-not $line) { Write-Warning ("  {0} 未出现在 gcovr 输出中" -f $t); continue }
    # 取行中的百分比列（如 "98%"），不是 Missing 列开头的行号
    $pct = -1
    foreach ($tok in ($line.Trim() -split '\s+')) { if ($tok -match '^(\d+)%$') { $pct = [int]$Matches[1] } }
    $mark = if ($pct -ge 80) { 'PASS' } else { 'BELOW' }
    Write-Host ("  [{0}] {1}" -f $mark, $line.Trim())
    if ($mark -eq 'PASS') { $hit++ }
}
Write-Host ("  达标 {0}/{1} 个目标文件（红线 80%）" -f $hit, $Targets.Count)
Write-Host '完成。' -ForegroundColor Green
