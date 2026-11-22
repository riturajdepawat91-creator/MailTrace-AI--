$ErrorActionPreference = 'Stop'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\MailTrace AI'
$expectedRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs'))
$resolvedInstall = [IO.Path]::GetFullPath($installDir)
$shortcutPaths = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\MailTrace AI.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'MailTrace AI.lnk'),
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\MailTrace Customer.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'MailTrace Customer.lnk')
)

if (-not $resolvedInstall.StartsWith($expectedRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to remove an installation path outside the current user Programs directory.'
}

$shortcutPaths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Remove-Item -LiteralPath $_ -Force }
if (Test-Path -LiteralPath $resolvedInstall) {
    Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
}
Write-Host 'MailTrace AI has been uninstalled for this Windows user.'
