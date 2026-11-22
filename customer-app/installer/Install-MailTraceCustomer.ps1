$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'app'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\MailTrace AI'
$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\MailTrace AI.lnk'
$desktopShortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'MailTrace AI.lnk'
$legacyShortcutPaths = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\MailTrace Customer.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'MailTrace Customer.lnk')
)
$exe = Join-Path $installDir 'MailTraceCustomer.exe'
$iconPath = Join-Path $installDir 'mailtrace-ai.ico'

if (-not (Test-Path -LiteralPath (Join-Path $source 'MailTraceCustomer.exe') -PathType Leaf)) {
    throw 'Installer files are incomplete. Extract the full setup ZIP before running this script.'
}
if (-not (Test-Path -LiteralPath (Join-Path $source 'mailtrace-ai.ico') -PathType Leaf)) {
    throw 'MailTrace logo icon is missing from this installer package.'
}

New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $installDir -Recurse -Force

$shell = New-Object -ComObject WScript.Shell
$legacyShortcutPaths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Remove-Item -LiteralPath $_ -Force }
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = $installDir
$shortcut.IconLocation = "$iconPath,0"
$shortcut.Description = 'MailTrace AI'
$shortcut.Save()

$desktopShortcut = $shell.CreateShortcut($desktopShortcutPath)
$desktopShortcut.TargetPath = $exe
$desktopShortcut.WorkingDirectory = $installDir
$desktopShortcut.IconLocation = "$iconPath,0"
$desktopShortcut.Description = 'MailTrace AI'
$desktopShortcut.Save()

Write-Host 'MailTrace AI is installed for this Windows user.'
Write-Host "Start Menu shortcut: $shortcutPath"
Write-Host "Desktop shortcut: $desktopShortcutPath"
Write-Host "Application: $exe"
Write-Host 'No .NET SDK is required on the target PC when the self-contained package is used.'
