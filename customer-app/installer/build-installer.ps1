param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64'
)

$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $appRoot 'windows\MailTraceCustomer.csproj'
$logoIcon = Join-Path $appRoot 'assets\mailtrace-ai.ico'
$outputRoot = Join-Path $appRoot 'dist'
$buildId = Get-Date -Format 'yyyyMMdd-HHmmss'
$publishDir = Join-Path $outputRoot "publish-$Runtime-$buildId"
$packageRoot = Join-Path $outputRoot "installer-$Runtime-$buildId"
$archive = Join-Path $outputRoot "MailTraceCustomer-$Runtime-Setup-$buildId.zip"

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw '.NET 8 SDK is required on the build machine. Install it, reopen PowerShell, and run this script again.'
}

$vsInstallations = @()
foreach ($root in @((Join-Path $env:ProgramFiles 'Microsoft Visual Studio'), (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'))) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
    foreach ($release in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue) {
        foreach ($edition in Get-ChildItem -LiteralPath $release.FullName -Directory -ErrorAction SilentlyContinue) {
            $msbuild = Join-Path $edition.FullName 'MSBuild\Current\Bin\MSBuild.exe'
            $tasksRoot = Join-Path $edition.FullName 'MSBuild\Microsoft\VisualStudio'
            if (Test-Path -LiteralPath $msbuild -PathType Leaf) {
                foreach ($version in Get-ChildItem -LiteralPath $tasksRoot -Directory -ErrorAction SilentlyContinue) {
                    $taskDirectory = Join-Path $version.FullName 'AppxPackage'
                    $vsInstallations += [pscustomobject]@{ MSBuild = $msbuild; Version = $version.Name; TaskDirectory = $taskDirectory }
                }
            }
        }
    }
}

$requiredAppxTasks = @(
    'Microsoft.Build.Packaging.Pri.Tasks.dll',
    'Microsoft.Build.AppxPackage.dll'
)
$visualStudio = $vsInstallations | Where-Object {
    $taskPath = $_.TaskDirectory
    @($requiredAppxTasks | Where-Object { -not (Test-Path -LiteralPath (Join-Path $taskPath $_) -PathType Leaf) }).Count -eq 0
} | Select-Object -First 1
if (-not $visualStudio) {
    throw "Visual Studio WinUI build tools are missing ($($requiredAppxTasks -join ', ')). In Visual Studio Installer, install the 'WinUI application development' workload, then reopen PowerShell."
}

if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw "WinUI project not found: $project"
}
if (-not (Test-Path -LiteralPath $logoIcon -PathType Leaf)) {
    throw "MailTrace logo icon not found: $logoIcon"
}

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null

& $visualStudio.MSBuild $project '-restore' '-target:Publish' `
    '-property:Configuration=Release' `
    "-property:RuntimeIdentifier=$Runtime" `
    '-property:SelfContained=true' `
    '-property:WindowsAppSDKSelfContained=true' `
    '-property:PublishSingleFile=false' `
    "-property:PublishDir=$publishDir\"
if ($LASTEXITCODE -ne 0) {
    throw "Visual Studio MSBuild publish failed with exit code $LASTEXITCODE"
}

$exe = Join-Path $publishDir 'MailTraceCustomer.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Publish completed but MailTraceCustomer.exe was not found.'
}

New-Item -ItemType Directory -Path (Join-Path $packageRoot 'app') -Force | Out-Null
Copy-Item -Path (Join-Path $publishDir '*') -Destination (Join-Path $packageRoot 'app') -Recurse -Force
Copy-Item -LiteralPath $logoIcon -Destination (Join-Path $packageRoot 'app\mailtrace-ai.ico')
$repositoryRoot = Split-Path -Parent $appRoot
$backendRoot = Join-Path $repositoryRoot 'backend'
$customerApiRoot = Join-Path $repositoryRoot 'customer_api'
$backendPython = Join-Path $backendRoot 'venv\Scripts\python.exe'
if ((Test-Path -LiteralPath (Join-Path $backendRoot 'main.py') -PathType Leaf) -and (Test-Path -LiteralPath $backendPython -PathType Leaf)) {
    Set-Content -LiteralPath (Join-Path $packageRoot 'app\backend-path.txt') -Value $backendRoot -Encoding UTF8
}
if (Test-Path -LiteralPath $customerApiRoot -PathType Container) {
    $packagedApi = Join-Path $packageRoot 'app\customer_api'
    New-Item -ItemType Directory -Path $packagedApi -Force | Out-Null
    Get-ChildItem -LiteralPath $customerApiRoot -File -Force | Copy-Item -Destination $packagedApi -Force
    Get-ChildItem -LiteralPath $customerApiRoot -Directory -Force |
        Where-Object { $_.Name -notin @('tests', '__pycache__') } |
        Copy-Item -Destination $packagedApi -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-MailTraceCustomer.ps1') -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Uninstall-MailTraceCustomer.ps1') -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $packageRoot
Compress-Archive -Path (Join-Path $packageRoot '*') -DestinationPath $archive -CompressionLevel Optimal

Write-Host "Installer package created: $archive"
Write-Host 'On the target PC, extract the ZIP and run Install-MailTraceCustomer.ps1.'
