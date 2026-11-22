$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$port = if ($env:MAILTRACE_CUSTOMER_PREVIEW_PORT) { [int]$env:MAILTRACE_CUSTOMER_PREVIEW_PORT } else { 4173 }
$existing = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($existing) { throw "Port $port is already in use. Set MAILTRACE_CUSTOMER_PREVIEW_PORT to an available local port." }
$node = (Get-Command node -ErrorAction Stop).Source
$server = Join-Path $appRoot 'server.mjs'
$stdout = Join-Path $appRoot '.preview.stdout.log'
$stderr = Join-Path $appRoot '.preview.stderr.log'
$process = Start-Process -FilePath $node -ArgumentList ('"' + $server + '"') -WorkingDirectory $appRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
Start-Sleep -Milliseconds 650
if ($process.HasExited) { throw "Preview server exited during startup. Check $stderr for a safe startup category." }
Write-Output "Preview URL: http://127.0.0.1:$port"
Write-Output "Preview process ID: $($process.Id)"
