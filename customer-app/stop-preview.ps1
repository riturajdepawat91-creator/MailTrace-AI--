$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$stderr = Join-Path $appRoot '.preview.stderr.log'
$match = Select-String -Path $stderr -Pattern 'Preview server could not start' -ErrorAction SilentlyContinue
if ($match) { Write-Output 'Preview startup failed; no matching server process was stopped.'; exit 1 }
$listeners = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $(if ($env:MAILTRACE_CUSTOMER_PREVIEW_PORT) { [int]$env:MAILTRACE_CUSTOMER_PREVIEW_PORT } else { 4173 }) -State Listen -ErrorAction SilentlyContinue
foreach ($listener in $listeners) {
  $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)" -ErrorAction SilentlyContinue
  if ($process -and $process.CommandLine -like '*customer-app*server.mjs*') {
    Stop-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
    Write-Output 'MailTrace Customer preview stopped.'
    exit 0
  }
}
Write-Output 'No MailTrace Customer preview server found.'
