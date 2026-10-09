$ErrorActionPreference = "Continue"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$BackendPath = Join-Path $ProjectRoot "backend"

$FrontendPath = Join-Path $ProjectRoot "frontend"

$BackendPort = 8000

$FrontendPort = 5503

# Use the project's installed dependencies with its configured Python 3.11.
$VenvConfig = Join-Path $BackendPath "venv\pyvenv.cfg"
$PythonExe = $null
$PythonSitePackages = Join-Path $BackendPath "venv\Lib\site-packages"

if (Test-Path $VenvConfig) {
    $PythonHome = (Get-Content $VenvConfig | Where-Object { $_ -match '^home\s*=' } | Select-Object -First 1) -replace '^home\s*=\s*', ''
    if ($PythonHome) {
        $CandidatePython = Join-Path $PythonHome.Trim() "python.exe"
        if (Test-Path $CandidatePython) {
            $PythonExe = $CandidatePython
        }
    }
}

if (-not $PythonExe) {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($PythonCommand) {
        $PythonExe = $PythonCommand.Source
    }
}

if (-not $PythonExe) {
    Write-Host "[ERROR] Python 3.11 was not found. Check backend\venv\pyvenv.cfg." -ForegroundColor Red
    Read-Host "Press ENTER to exit"
    exit 1
}

if (Test-Path $PythonSitePackages) {
    $env:PYTHONPATH = $PythonSitePackages
}

$BackendArguments = @(
    "-m",
    "uvicorn",
    "main:app",
    "--host",
    "127.0.0.1",
    "--port",
    "$BackendPort"
)
if ($env:MAILTRACE_RELOAD -eq "1") {
    $BackendArguments += "--reload"
}


function Test-PortRunning {

    param(
        [int]$Port
    )

    try {

        $connection = Get-NetTCPConnection `
            -LocalPort $Port `
            -State Listen `
            -ErrorAction SilentlyContinue

        return ($null -ne $connection)

    }

    catch {

        return $false

    }

}


function Wait-ForService {

    param(

        [string]$Url,

        [int]$Attempts = 20,

        [string]$ExpectedService,

        [string]$ExpectedContent

    )


    for ($i = 1; $i -le $Attempts; $i++) {

        try {

            $response = Invoke-WebRequest `
                -Uri $Url `
                -UseBasicParsing `
                -TimeoutSec 2 `
                -ErrorAction Stop


            if ($response.StatusCode -eq 200) {

                if ($ExpectedService) {
                    $servicePayload = $response.Content | ConvertFrom-Json -ErrorAction Stop
                    if ($servicePayload.status -eq "ok" -and $servicePayload.service -eq $ExpectedService) {
                        return $true
                    }
                }
                elseif ($ExpectedContent) {
                    if ($response.Content.Contains($ExpectedContent)) {
                        return $true
                    }
                }
                else {
                    return $true
                }

            }

        }

        catch {

        }


        Start-Sleep -Seconds 1

    }


    return $false

}


try {
    Clear-Host
}
catch {
    # Host terminals without an interactive RawUI can still use the launcher.
}


Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "           MAILTRACE AI STARTUP SYSTEM" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""


# ==========================================================
# BACKEND
# ==========================================================


if (Test-PortRunning $BackendPort) {

    Write-Host `
        "[OK] Backend already running on port $BackendPort" `
        -ForegroundColor Green

}

else {

    Write-Host `
        "[STARTING] Starting MailTrace AI backend..." `
        -ForegroundColor Yellow


    # Launch Python directly. A nested PowerShell -Command string breaks when
    # the project path contains spaces (as it does in this workspace).
    Start-Process `
        -FilePath $PythonExe `
        -ArgumentList $BackendArguments `
        -WorkingDirectory $BackendPath `
        -WindowStyle Hidden

}


Write-Host ""
Write-Host "[WAIT] Waiting for backend service..." -ForegroundColor Cyan


$BackendReady = Wait-ForService `
    -Url "http://127.0.0.1:$BackendPort/api/ready" `
    -ExpectedService "MailTrace AI Backend" `
    -Attempts 30


if ($BackendReady) {

    Write-Host `
        "[OK] Backend service is ready" `
        -ForegroundColor Green

}

else {

    Write-Host `
        "[ERROR] Backend failed to start" `
        -ForegroundColor Red


    Write-Host ""
    Write-Host `
        "Website will not open until backend is available." `
        -ForegroundColor Yellow


    Read-Host "Press ENTER to exit"

    exit 1

}


# ==========================================================
# FRONTEND
# ==========================================================


if (Test-PortRunning $FrontendPort) {

    Write-Host `
        "[OK] Frontend already running on port $FrontendPort" `
        -ForegroundColor Green

}

else {

    Write-Host `
        "[STARTING] Starting MailTrace AI frontend..." `
        -ForegroundColor Yellow


    Start-Process `
        -FilePath $PythonExe `
        -ArgumentList @(
            "-m",
            "http.server",
            "$FrontendPort",
            "--bind",
            "127.0.0.1"
        ) `
        -WorkingDirectory $FrontendPath `
        -WindowStyle Hidden

}


Write-Host ""
Write-Host "[WAIT] Waiting for frontend service..." -ForegroundColor Cyan


$FrontendReady = Wait-ForService `
    -Url "http://127.0.0.1:$FrontendPort/index.html" `
    -ExpectedContent "<title>MailTrace AI | Email Forensic Intelligence</title>" `
    -Attempts 20


if ($FrontendReady) {

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "             MAILTRACE AI IS READY" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""

    Write-Host `
        "Backend  : http://127.0.0.1:$BackendPort" `
        -ForegroundColor Cyan

    Write-Host `
        "Frontend : http://127.0.0.1:$FrontendPort/index.html" `
        -ForegroundColor Cyan


    Start-Sleep -Seconds 1


    try {
        Start-Process `
            "http://127.0.0.1:$FrontendPort/index.html" `
            -ErrorAction Stop
    }
    catch {
        Write-Host `
            "[INFO] Open http://127.0.0.1:$FrontendPort/index.html in your browser." `
            -ForegroundColor Yellow
    }

}

else {

    Write-Host ""
    Write-Host `
        "[ERROR] Frontend failed to start." `
        -ForegroundColor Red

}


Write-Host ""
Read-Host "Press ENTER to close launcher"
