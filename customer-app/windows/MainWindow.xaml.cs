using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Web.WebView2.Core;

namespace MailTrace.Customer;

public sealed partial class MainWindow : Window
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(2.2) };
    private const string BackendStartSemaphoreName = "Local\\MailTraceCustomerBackendStart";
    private const string CustomerApiStartSemaphoreName = "Local\\MailTraceCustomerApiStart";
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private DispatcherQueueTimer? _telemetryTimer;
    private TimeSpan _lastCpu;
    private TimeSpan _lastCpuSample;
    private long _lastNetworkBytes;
    private long _lastNetworkTicks;

    public MainWindow()
    {
        InitializeComponent();
        Title = "MailTrace – AI Forensics";
        Browser.Loaded += Browser_Loaded;
    }

    private async void Browser_Loaded(object sender, RoutedEventArgs e)
    {
        Browser.Loaded -= Browser_Loaded;
        try
        {
            await Browser.EnsureCoreWebView2Async();
            Browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            Browser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
            Browser.CoreWebView2.WebMessageReceived += Browser_WebMessageReceived;
            Browser.NavigationCompleted += Browser_NavigationCompleted;
            var webRoot = Path.Combine(AppContext.BaseDirectory, "Assets", "Web");
            Browser.CoreWebView2.SetVirtualHostNameToFolderMapping(
                "mailtrace.invalid",
                webRoot,
                CoreWebView2HostResourceAccessKind.DenyCors);
            Browser.Source = new Uri("https://mailtrace.invalid/index.html");
            _ = EnsureCustomerApiAvailableAsync();
            StartTelemetry();
        }
        catch
        {
            // Keep service details and user data out of diagnostics. The shell
            // stays available and the user sees the built-in webview fallback.
        }
    }

    private async void Browser_NavigationCompleted(WebView2 sender, Microsoft.Web.WebView2.Core.CoreWebView2NavigationCompletedEventArgs args)
    {
        if (!args.IsSuccess) return;
        try { await Browser.ExecuteScriptAsync("document.body.classList.add('desktop-host')"); }
        catch { }
    }

    private async void Browser_WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        try
        {
            if (!Uri.TryCreate(args.Source, UriKind.Absolute, out var source) ||
                source.Scheme != "https" || !source.Host.Equals("mailtrace.invalid", StringComparison.OrdinalIgnoreCase))
                return;
            using var message = JsonDocument.Parse(args.WebMessageAsJson);
            var root = message.RootElement;
            if (!root.TryGetProperty("type", out var type)) return;
            if (type.GetString() == "customer-api-status")
            {
                await EnsureCustomerApiAvailableAsync();
                var customerRequestId = root.TryGetProperty("requestId", out var statusRequest) ? statusRequest.GetString() : null;
                var health = await CheckCustomerApiHealthAsync("http://127.0.0.1:8100");
                JsonElement? auth = null;
                if (IsCustomerApiReachable(health))
                {
                    try
                    {
                        using var response = await Http.GetAsync("http://127.0.0.1:8100/v1/auth/config");
                        using var config = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                        auth = config.RootElement.Clone();
                    }
                    catch { }
                }
                object session = IsCustomerApiReachable(health)
                    ? await OidcSessionManager.Instance.GetStatusAsync()
                    : new { login_supported = false, authenticated = false, reauth_required = false };
                Browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "customer-api-result", requestId = customerRequestId, online = IsCustomerApiReachable(health), auth, session }));
                return;
            }
            if (type.GetString() == "customer-api-operation")
            {
                var operationRequestId = root.TryGetProperty("requestId", out var operationRequest) ? operationRequest.GetString() : null;
                var operation = root.TryGetProperty("operation", out var operationValue) ? operationValue.GetString() : null;
                object operationResult;
                try
                {
                    operationResult = operation switch
                    {
                        "login" => await OidcSessionManager.Instance.LoginAsync(),
                        "logout" => await OidcSessionManager.Instance.LogoutAsync(),
                        "mailboxes" or "connect-gmail" or "disconnect-gmail" or "sync-status" or "sync-now" => await OidcSessionManager.Instance.ExecuteCustomerOperationAsync(operation),
                        _ => new { ok = false, state = "OPERATION_NOT_ALLOWED" },
                    };
                }
                catch (UnauthorizedAccessException) { operationResult = new { ok = false, state = "SIGN_IN_REQUIRED" }; }
                catch (Exception ex) { operationResult = new { ok = false, state = "REQUEST_FAILED", error_category = ex.GetType().Name }; }
                Browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "customer-api-operation-result", requestId = operationRequestId, operation, result = operationResult }));
                return;
            }
            if (type.GetString() != "health-check") return;
            var requestId = root.TryGetProperty("requestId", out var requestElement) ? requestElement.GetString() : null;
            var baseUrl = root.TryGetProperty("baseUrl", out var baseElement) ? baseElement.GetString() : null;
            var result = IsDefaultBackend(baseUrl)
                ? await EnsureBackendAvailableAsync(baseUrl!)
                : await CheckHealthAsync(baseUrl);
            Browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new
            {
                type = "health-result",
                requestId,
                health = result.Health,
                ready = result.Ready,
                error = result.Error,
            }));
        }
        catch
        {
            try
            {
                Browser.CoreWebView2.PostWebMessageAsJson("{\"type\":\"health-result\",\"error\":\"Local service check failed.\"}");
            }
            catch { }
        }
    }

    private static bool IsDefaultBackend(string? value)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
            uri.Scheme == Uri.UriSchemeHttp && uri.Port == 8002 &&
            (uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
             uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsCustomerApiReachable(HealthResult result)
    {
        return result.Health is JsonElement health &&
            health.TryGetProperty("status", out var status) && status.GetString() == "ok" &&
            health.TryGetProperty("service", out var service) && service.GetString() == "MailTrace Customer API";
    }

    private static async Task EnsureCustomerApiAvailableAsync()
    {
        const string apiBase = "http://127.0.0.1:8100";
        var current = await CheckCustomerApiHealthAsync(apiBase);
        if (IsCustomerApiReachable(current)) return;

        using var launchSemaphore = new Semaphore(1, 1, CustomerApiStartSemaphoreName);
        var ownsSemaphore = false;
        try
        {
            ownsSemaphore = await Task.Run(() => launchSemaphore.WaitOne(TimeSpan.FromSeconds(15)));
            if (!ownsSemaphore) return;
            current = await CheckCustomerApiHealthAsync(apiBase);
            if (IsCustomerApiReachable(current)) return;

            var backendDirectory = ResolveBackendDirectory();
            if (backendDirectory is null) return;
            var bundledAppDirectory = AppContext.BaseDirectory;
            var appDirectory = Directory.Exists(Path.Combine(bundledAppDirectory, "customer_api"))
                ? bundledAppDirectory
                : Path.GetFullPath(Path.Combine(backendDirectory, ".."));
            if (!Directory.Exists(Path.Combine(appDirectory, "customer_api"))) return;
            var python = Path.Combine(backendDirectory, "venv", "Scripts", "python.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = python,
                WorkingDirectory = backendDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add("-m");
            startInfo.ArgumentList.Add("uvicorn");
            startInfo.ArgumentList.Add("customer_api.main:app");
            startInfo.ArgumentList.Add("--app-dir");
            startInfo.ArgumentList.Add(appDirectory);
            startInfo.ArgumentList.Add("--host");
            startInfo.ArgumentList.Add("127.0.0.1");
            startInfo.ArgumentList.Add("--port");
            startInfo.ArgumentList.Add("8100");
            startInfo.ArgumentList.Add("--no-access-log");
            var process = Process.Start(startInfo);
            if (process is null) return;
            process.OutputDataReceived += (_, _) => { };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(20) && !process.HasExited)
            {
                await Task.Delay(500);
                if (IsCustomerApiReachable(await CheckCustomerApiHealthAsync(apiBase))) return;
            }
        }
        catch { /* UI remains available; customer API reports unavailable. */ }
        finally { if (ownsSemaphore) launchSemaphore.Release(); }
    }

    private static async Task<HealthResult> CheckCustomerApiHealthAsync(string apiBase)
    {
        try
        {
            using var response = await Http.GetAsync(new Uri(new Uri(apiBase), "/health"));
            using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            return new HealthResult(document.RootElement.Clone(), null, response.IsSuccessStatusCode ? null : "Customer API is unavailable.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new HealthResult(null, null, "Customer API is unavailable.");
        }
    }

    private static bool IsApiReachable(HealthResult result)
    {
        return result.Health is JsonElement health &&
            health.TryGetProperty("status", out var status) &&
            status.GetString() == "ok" &&
            health.TryGetProperty("service", out var service) &&
            service.GetString() == "MailTrace AI Backend";
    }

    private static async Task<HealthResult> EnsureBackendAvailableAsync(string baseUrl)
    {
        var current = await CheckHealthAsync(baseUrl);
        if (IsApiReachable(current)) return current;

        using var launchSemaphore = new Semaphore(1, 1, BackendStartSemaphoreName);
        var ownsSemaphore = false;
        try
        {
            ownsSemaphore = await Task.Run(() => launchSemaphore.WaitOne(TimeSpan.FromSeconds(25)));
            if (!ownsSemaphore)
                return current with { Error = "Another MailTrace startup is in progress; the API is not ready yet." };

            current = await CheckHealthAsync(baseUrl);
            if (IsApiReachable(current)) return current;

            var backendDirectory = ResolveBackendDirectory();
            if (backendDirectory is null)
                return current with { Error = "Local backend path or its Python virtual environment is not configured." };

            var python = Path.Combine(backendDirectory, "venv", "Scripts", "python.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = python,
                WorkingDirectory = backendDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            startInfo.ArgumentList.Add("-m");
            startInfo.ArgumentList.Add("uvicorn");
            startInfo.ArgumentList.Add("main:app");
            startInfo.ArgumentList.Add("--host");
            startInfo.ArgumentList.Add("127.0.0.1");
            startInfo.ArgumentList.Add("--port");
            startInfo.ArgumentList.Add("8002");
            using var process = Process.Start(startInfo);
            if (process is null)
                return current with { Error = "The local backend process could not be started." };

            process.OutputDataReceived += (_, _) => { };
            process.ErrorDataReceived += (_, _) => { };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var deadline = Stopwatch.StartNew();
            while (deadline.Elapsed < TimeSpan.FromSeconds(25))
            {
                await Task.Delay(700);
                current = await CheckHealthAsync(baseUrl);
                if (IsApiReachable(current)) return current;
                if (process.HasExited) break;
            }

            return current with { Error = "The local backend did not become ready. Check its Python environment and startup configuration." };
        }
        catch
        {
            return current with { Error = "The local backend could not be started or reached." };
        }
        finally
        {
            if (ownsSemaphore) launchSemaphore.Release();
        }
    }

    private static string? ResolveBackendDirectory()
    {
        try
        {
            var configured = Environment.GetEnvironmentVariable("MAILTRACE_BACKEND_DIR");
            if (string.IsNullOrWhiteSpace(configured))
            {
                var pathFile = Path.Combine(AppContext.BaseDirectory, "backend-path.txt");
                if (File.Exists(pathFile)) configured = File.ReadAllText(pathFile).Trim();
            }
            if (string.IsNullOrWhiteSpace(configured)) return null;

            var fullPath = Path.GetFullPath(configured.Trim());
            return File.Exists(Path.Combine(fullPath, "main.py")) &&
                File.Exists(Path.Combine(fullPath, "venv", "Scripts", "python.exe"))
                    ? fullPath
                    : null;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<HealthResult> CheckHealthAsync(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var baseUri) ||
            baseUri.Scheme is not ("http" or "https") ||
            !(IPAddress.TryParse(baseUri.Host, out var ip) && IPAddress.IsLoopback(ip) || baseUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
            return new HealthResult(null, null, "Only a loopback MailTrace API address is allowed.");

        try
        {
            using var healthResponse = await Http.GetAsync(new Uri(baseUri, "/api/health"));
            using var readyResponse = await Http.GetAsync(new Uri(baseUri, "/api/ready"));
            using var healthDocument = JsonDocument.Parse(await healthResponse.Content.ReadAsStringAsync());
            using var readyDocument = JsonDocument.Parse(await readyResponse.Content.ReadAsStringAsync());
            var health = healthDocument.RootElement.Clone();
            var ready = readyDocument.RootElement.Clone();
            return new HealthResult(health, ready, healthResponse.IsSuccessStatusCode ? null : "MailTrace API reported an unavailable state.");
        }
        catch (TaskCanceledException)
        {
            return new HealthResult(null, null, "Local MailTrace health/readiness check timed out.");
        }
        catch (HttpRequestException)
        {
            return new HealthResult(null, null, "Local MailTrace health/readiness endpoints are unavailable.");
        }
        catch (JsonException)
        {
            return new HealthResult(null, null, "MailTrace health/readiness response was invalid.");
        }
    }

    private void StartTelemetry()
    {
        _telemetryTimer = DispatcherQueue.CreateTimer();
        _telemetryTimer.Interval = TimeSpan.FromSeconds(2);
        _telemetryTimer.Tick += (_, _) => PostTelemetry();
        _telemetryTimer.Start();
    }

    private void PostTelemetry()
    {
        try
        {
            _process.Refresh();
            var cpu = _process.TotalProcessorTime;
            var now = _clock.Elapsed;
            var cpuPercent = _lastCpuSample == TimeSpan.Zero ? (double?)null : Math.Clamp((cpu - _lastCpu).TotalMilliseconds / Math.Max(1, (now - _lastCpuSample).TotalMilliseconds) / Environment.ProcessorCount * 100, 0, 100);
            _lastCpu = cpu;
            _lastCpuSample = now;
            var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
            double? memoryPercent = null;
            if (GlobalMemoryStatusEx(ref status) && status.TotalPhysical > 0)
                memoryPercent = Math.Clamp((status.TotalPhysical - status.AvailablePhysical) * 100d / status.TotalPhysical, 0, 100);

            var root = Path.GetPathRoot(AppContext.BaseDirectory);
            double? diskPercent = null;
            if (!string.IsNullOrEmpty(root))
            {
                var drive = new DriveInfo(root);
                if (drive.IsReady && drive.TotalSize > 0) diskPercent = Math.Clamp((drive.TotalSize - drive.AvailableFreeSpace) * 100d / drive.TotalSize, 0, 100);
            }

            long networkBytes = NetworkInterface.GetAllNetworkInterfaces()
                .Where(item => item.OperationalStatus == OperationalStatus.Up && item.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Sum(item => item.GetIPv4Statistics().BytesReceived + item.GetIPv4Statistics().BytesSent);
            var ticks = _clock.ElapsedTicks;
            double? networkMbps = null;
            if (_lastNetworkTicks > 0 && ticks > _lastNetworkTicks)
            {
                var seconds = (ticks - _lastNetworkTicks) / (double)Stopwatch.Frequency;
                networkMbps = Math.Max(0, (networkBytes - _lastNetworkBytes) * 8d / seconds / 1_000_000d);
            }
            _lastNetworkBytes = networkBytes;
            _lastNetworkTicks = ticks;
            var value = new { cpuPercent, memoryPercent, diskPercent, networkMbps };
            Browser.CoreWebView2?.PostWebMessageAsJson(JsonSerializer.Serialize(new { type = "telemetry", value }));
        }
        catch { }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    private sealed record HealthResult(JsonElement? Health, JsonElement? Ready, string? Error);
}
