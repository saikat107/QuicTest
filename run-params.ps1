# run-params.ps1
$ParamsDir = ".\.deeptest\parameters"
$Pattern   = "*.params.txt"

# Where logs go
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
  Write-Host "Running: $($f.FullName)"

  $cmd = Get-Content -Path $f.FullName -Raw
  $cmd = $cmd.Trim()

  if ([string]::IsNullOrWhiteSpace($cmd)) {
    Write-Host "SKIP: empty command file."
    $results += [pscustomobject]@{ File=$f.Name; Status="SKIPPED_EMPTY"; ExitCode=$null }
    continue
  }

  $safeBase = [IO.Path]::GetFileNameWithoutExtension($f.Name)
  $outLog   = Join-Path $LogDir "$safeBase.out.log"
  $errLog   = Join-Path $LogDir "$safeBase.err.log"

  # Capture stdout/stderr for this file
  "COMMAND:" | Set-Content -Path $outLog
  $cmd       | Add-Content -Path $outLog
  ""         | Add-Content -Path $outLog

  try {
    # Run the command in a child PowerShell so $LASTEXITCODE is meaningful per run
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1
    $exitCode = $LASTEXITCODE

    # Split output: we already redirected 2>&1 into $output, so log it all to out
    $output | Add-Content -Path $outLog

    if ($exitCode -eq 0) {
      Write-Host "OK (exit $exitCode)"
      $results += [pscustomobject]@{ File=$f.Name; Status="OK"; ExitCode=$exitCode }
    } else {
      Write-Host "FAIL (exit $exitCode)  -> logs in $LogDir"
      # Also put a short marker in err log
      "ExitCode: $exitCode" | Set-Content -Path $errLog
      $output | Add-Content -Path $errLog
      $results += [pscustomobject]@{ File=$f.Name; Status="FAIL"; ExitCode=$exitCode }
    }
  }
  catch {
    Write-Host "ERROR: $($_.Exception.Message)  -> logs in $LogDir"
    $_ | Out-String | Set-Content -Path $errLog
    $results += [pscustomobject]@{ File=$f.Name; Status="ERROR"; ExitCode=$null }
  }
}

Write-Host "============================================================"
Write-Host "Summary:"
$results | Format-Table -AutoSize

# Return non-zero if any failed/error (useful in CI)
if ($results | Where-Object { $_.Status -in @("FAIL","ERROR") }) {
  exit 1
}
exit 0