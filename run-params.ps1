# run-all-params.ps1
$ParamsDir = "C:\Users\saikatc\workspace\DeepTest\QuicTest\.deeptest\parameters"
$Pattern   = "*.ps1"

$LogDir = Join-Path $ParamsDir "_logs"
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Use pwsh if available, otherwise fall back to Windows PowerShell
$PsExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh.exe" } else { "powershell.exe" }

$runnerName = Split-Path -Leaf $PSCommandPath

$files = Get-ChildItem -Path $ParamsDir -Filter $Pattern -File |
  Where-Object { $_.Name -ne $runnerName } |
  Sort-Object FullName

if (-not $files) {
  Write-Host "No files found matching '$Pattern' under: $ParamsDir"
  exit 0
}

$results = @()

foreach ($f in $files) {
  $base   = [IO.Path]::GetFileNameWithoutExtension($f.Name)
  $log    = Join-Path $LogDir "$base.log"

  ("=" * 80) | Tee-Object -FilePath $log -Append
  ("RUN  : {0}" -f $f.FullName) | Tee-Object -FilePath $log -Append
  ("TIME : {0}" -f (Get-Date -Format o)) | Tee-Object -FilePath $log -Append
  ("PS   : {0}" -f $PsExe) | Tee-Object -FilePath $log -Append
  ("=" * 80) | Tee-Object -FilePath $log -Append

  # Tee combined stdout+stderr live to terminal + file
  & $PsExe -NoProfile -ExecutionPolicy Bypass -File $f.FullName 2>&1 |
    Tee-Object -FilePath $log -Append

  $exitCode = $LASTEXITCODE

  ("-" * 80) | Tee-Object -FilePath $log -Append
  ("EXIT : {0}" -f $exitCode) | Tee-Object -FilePath $log -Append
  ("DONE : {0}" -f (Get-Date -Format o)) | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append

  $status = if ($exitCode -eq 0) { "OK" } else { "FAIL" }
  $results += [pscustomobject]@{ File = $f.Name; Status = $status; ExitCode = $exitCode }
}

Write-Host "Summary:"
$results | Format-Table -AutoSize

if ($results | Where-Object { $_.Status -eq "FAIL" }) { exit 1 }
exit 0