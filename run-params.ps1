# run-all-params.ps1
$ParamsDir = "C:\Users\saikatc\workspace\DeepTest\QuicTest\.deeptest\parameters"
$Pattern   = "*.ps1"

# ----------------------------
# UTF-8 everywhere (no BOM)
# ----------------------------
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding  = $utf8NoBom
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom

# Make common cmdlets default to UTF-8 when they support -Encoding
$PSDefaultParameterValues['*:Encoding'] = 'utf8'

# Force console codepage to UTF-8 (helps stop "ΓùÅ" junk in terminal)
try { chcp 65001 | Out-Null } catch {}

# ----------------------------
# Logging setup
# ----------------------------
$LogDir = Join-Path $ParamsDir "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Prefer pwsh (PowerShell 7) if available, else Windows PowerShell
$PsExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh.exe" } else { "powershell.exe" }

# Helper: write to terminal AND append UTF-8 to log
function Tee-Line {
  param(
    [Parameter(Mandatory)] [string] $Path,
    [Parameter(ValueFromPipeline)] $Line
  )
  process {
    # show in terminal
    $Line
    # write to log in UTF-8
    Add-Content -Path $Path -Value ($Line.ToString()) -Encoding utf8
  }
}

$runnerName = if ($PSCommandPath) { Split-Path -Leaf $PSCommandPath } else { $null }

$files = Get-ChildItem -Path $ParamsDir -Filter $Pattern -File |
  Where-Object { -not $runnerName -or $_.Name -ne $runnerName } |
  Sort-Object FullName

if (-not $files) {
  Write-Host "No files found matching '$Pattern' under: $ParamsDir"
  exit 0
}

$results = @()

foreach ($f in $files) {
  $base = [IO.Path]::GetFileNameWithoutExtension($f.Name)
  $log  = Join-Path $LogDir "$base.log"

  ("=" * 80) | Tee-Line -Path $log
  ("RUN  : {0}" -f $f.FullName) | Tee-Line -Path $log
  ("TIME : {0}" -f (Get-Date -Format o)) | Tee-Line -Path $log
  ("PS   : {0}" -f $PsExe) | Tee-Line -Path $log
  ("=" * 80) | Tee-Line -Path $log

  # Run script in child PowerShell with UTF-8 enforced and ALL streams merged (*>&1)
  $escapedPath = $f.FullName.Replace("'", "''")
  $childCommand = @"
& {
  `$utf8 = [System.Text.UTF8Encoding]::new(`$false)
  [Console]::InputEncoding  = `$utf8
  [Console]::OutputEncoding = `$utf8
  `$OutputEncoding = `$utf8

  # Run the target script; merge all PS streams to success output so parent can capture/tee
  & '$escapedPath' *>&1
}
"@

  & $PsExe -NoProfile -ExecutionPolicy Bypass -Command $childCommand 2>&1 |
    ForEach-Object { $_ } | Tee-Line -Path $log

  $exitCode = $LASTEXITCODE

  ("-" * 80) | Tee-Line -Path $log
  ("EXIT : {0}" -f $exitCode) | Tee-Line -Path $log
  ("DONE : {0}" -f (Get-Date -Format o)) | Tee-Line -Path $log
  "" | Tee-Line -Path $log

  $status = if ($exitCode -eq 0) { "OK" } else { "FAIL" }
  $results += [pscustomobject]@{ File = $f.Name; Status = $status; ExitCode = $exitCode }
}

Write-Host "Summary:"
$results | Format-Table -AutoSize

if ($results | Where-Object { $_.Status -eq "FAIL" }) { exit 1 }
exit 0