# Diag: run individual commands whose batch result was ambiguous, dump raw output.
$ErrorActionPreference = 'Continue'
$ROOT = Split-Path $PSScriptRoot -Parent
$BK   = Join-Path $ROOT 'dbkp\bin\bk.exe'
$VIN  = Join-Path $env:TEMP 'dbkp_verify'
$SRC  = Join-Path $VIN 'src'
$WORK = Join-Path $VIN 'diag'
if (Test-Path $WORK) { Remove-Item $WORK -Recurse -Force }
New-Item -ItemType Directory -Path $WORK | Out-Null

function Show { param([string]$Tag, [string[]]$Cmd)
    Write-Output "----- $Tag -----"
    Write-Output ("> bk " + ($Cmd -join ' '))
    $o = & $BK @Cmd 2>&1 | Out-String
    Write-Output ("rc=" + $LASTEXITCODE)
    Write-Output ($o.Trim())
    Write-Output ""
}

Show 'help' @('--help')
Show 'baseline backup' @('backup', $SRC, (Join-Path $WORK 'base.dbkp'), '-a', 'none')
Show 'info of baseline' @('info', (Join-Path $WORK 'base.dbkp'))
Show 'exclude backup' @('backup', $SRC, (Join-Path $WORK 'ex.dbkp'), '-a', 'none', '--exclude', 'b.tmp')
Show 'info of exclude' @('info', (Join-Path $WORK 'ex.dbkp'))
Show 'name backup' @('backup', $SRC, (Join-Path $WORK 'nm.dbkp'), '-a', 'none', '--name', '*.txt')
Show 'info of name' @('info', (Join-Path $WORK 'nm.dbkp'))
Show 'type-F backup' @('backup', $SRC, (Join-Path $WORK 'ty.dbkp'), '-a', 'none', '--type', 'F')
Show 'hardlink on' @('backup', $SRC, (Join-Path $WORK 'hd.dbkp'), '-a', 'none')
Show 'copy mode' @('backup', $SRC, (Join-Path $WORK 'cp'), '--copy')
Show 'comment' @('backup', $SRC, (Join-Path $WORK 'cmt.dbkp'), '-a', 'none', '-m', 'hello-comment')
Show 'info of comment' @('info', (Join-Path $WORK 'cmt.dbkp'))
Show 'schedule once' @('schedule', $SRC, (Join-Path $WORK 'sch'), '--every', '1s', '--times', '2', '--keep', '1', '-a', 'none')
Show 'wrong password restore' @('restore', (Join-Path $WORK 'base.dbkp'), (Join-Path $WORK 'wp'), '--force', '-p', 'zzz')
