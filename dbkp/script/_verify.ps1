# ============================================================================
#  _verify.ps1 -- 增量构建单元测试程序并运行，结果落盘
#  usage: powershell -File script/_verify.ps1 [-filter Meta]
#  为什么要脚本：命令行太长会被终端折行截断，改用短命令调用本脚本
# ============================================================================
param([string]$filter = "")
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
[Environment]::CurrentDirectory = (Get-Location).Path

$env:DBKP_TEST_FILTER = $filter
"run start: $(Get-Date)  filter='$filter'" | Out-File -Encoding utf8 build.log
mingw32-make -j4 bin/bk_test.exe 2>&1 | Out-File -Encoding utf8 -Append build.log
"make rc=$LASTEXITCODE" | Add-Content build.log
if ($LASTEXITCODE -ne 0) { exit 2 }

.\bin\bk_test.exe 2>&1 | Out-File -Encoding utf8 ut.log
"test rc=$LASTEXITCODE" | Add-Content ut.log
Write-Host ("test rc=" + $LASTEXITCODE)
exit $LASTEXITCODE
