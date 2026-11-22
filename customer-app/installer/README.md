# MailTrace Customer Windows installer package

This creates a per-user Windows install package from the isolated WinUI 3 host. The published app is self-contained, so the target computer does not need the .NET SDK. The build computer needs .NET 8 SDK, Visual Studio's **WinUI application development** workload, and Windows App SDK NuGet restore access. In Visual Studio Installer, choose **Modify** and select that workload. (For Visual Studio 17.10–17.12 it may be named **Windows application development**.) The script publishes through Visual Studio MSBuild so it uses the WinUI/PRI build tasks installed by that workload.

## Build

From PowerShell in the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
& .\customer-app\installer\build-installer.ps1
```

The output is a timestamped ZIP under `customer-app\dist`, for example `MailTraceCustomer-win-x64-Setup-20261122-103000.zip`. Use `-Runtime win-arm64` for an ARM64 package. The script publishes in Release mode with Windows App SDK self-contained deployment, then packages the app and install/uninstall scripts.

## Install on a Windows PC

Extract the ZIP, right-click `Install-MailTraceCustomer.ps1`, and choose **Run with PowerShell**. It copies the app to `%LOCALAPPDATA%\Programs\MailTrace Customer` and adds Start Menu and Desktop shortcuts named **MailTrace AI**, using the bundled MailTrace shield-envelope logo as the shortcut icon. Double-click the desktop icon to launch it. No administrator rights are requested. To remove it, run `Uninstall-MailTraceCustomer.ps1` from the extracted package; it removes the shortcuts and installed app folder.

When the backend source and `backend\venv\Scripts\python.exe` exist on the build machine, the package includes a local backend path hint for that machine. At app startup, the desktop host checks `/api/health`; if the default loopback service is not running, it starts the existing backend hidden on port 8002 with its normal environment and background-worker settings. When moving the installer to another PC, configure the `MAILTRACE_BACKEND_DIR` environment variable for that Windows user to the backend directory containing `main.py` and `venv\Scripts\python.exe`. The app does not bundle the backend, database, `.env`, or credentials.

This is an unsigned internal/demo package. Windows SmartScreen may show a warning because it has no publisher signature. A trusted code-signing certificate is required before distributing it broadly or presenting a verified publisher identity.

The customer app remains separate from the internal SOC app. This installer does not start or install a backend, agent, service, or mailbox connector.
