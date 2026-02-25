# run-params.ps1
$ParamsDir = "C:\Users\saikatc\workspace\DeepTest\QuicTest\.deeptest\parameters"
$Pattern   = "*.ps1"

$LogDir = Join-Path $ParamsDir "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$files = Get-ChildItem -Path $ParamsDir -Filter $Pattern -File | Sort-Object FullName
if (-not $files) {
  Write-Host "No files found matching '$Pattern' under: $ParamsDir"
  exit 0
}

$results = @()

foreach ($f in $files) {
  Write-Host "============================================================"
  Write-Host "Running script: $($f.FullName)"

  $base   = [IO.Path]::GetFileNameWithoutExtension($f.Name)
  $outLog = Join-Path $LogDir "$base.out.log"
  $errLog = Join-Path $LogDir "$base.err.log"

  # Header in logs
  "SCRIPT: $($f.FullName)" | Set-Content -Path $outLog
  "START : $(Get-Date -Format o)" | Add-Content -Path $outLog
  "" | Add-Content -Path $outLog

  try {
    # Run in child pwsh/powershell depending on what you have.
    # Using powershell.exe for Windows PowerShell 5.1; switch to pwsh.exe if you prefer PS7.
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f.FullName 2>&1
    $exitCode = $LASTEXITCODE

    $output | Add-Content -Path $outLog
    "" | Add-Content -Path $outLog
    "END   : $(Get-Date -Format o)" | Add-Content -Path $outLog
    "EXIT  : $exitCode" | Add-Content -Path $outLog

    if ($exitCode -eq 0) {
      Write-Host "OK (exit $exitCode)"
      $results += [pscustomobject]@{ File=$f.Name; Status="OK"; ExitCode=$exitCode }
    } else {
      Write-Host "FAIL (exit $exitCode) -> logs in $LogDir"
      "ExitCode: $exitCode" | Set-Content -Path $errLog
      $output | Add-Content -Path $errLog
      $results += [pscustomobject]@{ File=$f.Name; Status="FAIL"; ExitCode=$exitCode }
    }
  }
  catch {
    Write-Host "ERROR: $($_.Exception.Message) -> logs in $LogDir"
    $_ | Out-String | Set-Content -Path $errLog
    $results += [pscustomobject]@{ File=$f.Name; Status="ERROR"; ExitCode=$null }
  }
}

Write-Host "============================================================"
Write-Host "Summary:"
$results | Format-Table -AutoSize

# Fail the runner if any scripts failed/error (useful for CI)
if ($results | Where-Object { $_.Status -in @("FAIL","ERROR") }) { exit 1 }
exit 0