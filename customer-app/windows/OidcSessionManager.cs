using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace MailTrace.Customer;

/// <summary>Native OIDC Authorization Code + PKCE client. Tokens never leave this host.</summary>
internal sealed class OidcSessionManager
{
    private const string Api = "http://127.0.0.1:8100";
    private static readonly HttpClient Http = new(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(20) };
    private static readonly Lazy<OidcSessionManager> LazyInstance = new(() => new OidcSessionManager());
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly DpapiRefreshTokenStore _tokenStore = new();
    private string? _accessToken;
    private string? _refreshToken;
    private string? _issuer;
    private string? _clientId;
    private DateTimeOffset _accessExpiresAt;
    private bool _reauthRequired;

    public static OidcSessionManager Instance => LazyInstance.Value;

    public async Task<object> GetStatusAsync()
    {
        var config = await GetConfigAsync();
        if (config is null || !config.LoginSupported)
            return new { login_supported = false, authenticated = false, reauth_required = false };
        await RestoreAsync(config);
        if (string.IsNullOrEmpty(_accessToken))
            return new { login_supported = true, authenticated = false, reauth_required = _reauthRequired };
        try
        {
            using var response = await SendApiAsync(HttpMethod.Get, "/v1/me", null);
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == HttpStatusCode.Unauthorized) ClearInMemory();
                return new { login_supported = true, authenticated = false, reauth_required = true };
            }
            using var me = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            using var mailboxesResponse = await SendApiAsync(HttpMethod.Get, "/v1/mailboxes", null);
            JsonElement? mailboxes = null;
            if (mailboxesResponse.IsSuccessStatusCode)
            {
                using var mailboxesJson = JsonDocument.Parse(await mailboxesResponse.Content.ReadAsStringAsync());
                mailboxes = mailboxesJson.RootElement.Clone();
            }
            using var syncResponse = await SendApiAsync(HttpMethod.Get, "/v1/sync/status", null);
            JsonElement? sync = null;
            if (syncResponse.IsSuccessStatusCode)
            {
                using var syncJson = JsonDocument.Parse(await syncResponse.Content.ReadAsStringAsync());
                sync = syncJson.RootElement.Clone();
            }
            return new { login_supported = true, authenticated = true, reauth_required = false, roles = me.RootElement.TryGetProperty("roles", out var roles) ? roles.Clone() : default, mailboxes, sync };
        }
        catch
        {
            return new { login_supported = true, authenticated = false, reauth_required = true };
        }
    }

    public async Task<object> LoginAsync()
    {
        await _gate.WaitAsync();
        try
        {
            var config = await GetConfigAsync();
            if (config is null || !config.LoginSupported)
                return new { ok = false, state = "CONFIGURATION_UNAVAILABLE" };
            var discovery = await DiscoverAsync(config);
            var (redirectUri, code, expectedState, nonce, verifier) = await AuthorizeInSystemBrowserAsync(discovery, config);
            using var tokenResponse = await Http.PostAsync(discovery.TokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = config.ClientId,
                ["code"] = code,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = verifier,
            }));
            if (!tokenResponse.IsSuccessStatusCode)
                return new { ok = false, state = "TOKEN_EXCHANGE_FAILED" };
            using var tokenJson = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
            var access = ReadString(tokenJson.RootElement, "access_token");
            var idToken = ReadString(tokenJson.RootElement, "id_token");
            var refresh = ReadString(tokenJson.RootElement, "refresh_token");
            var expiresIn = ReadInt(tokenJson.RootElement, "expires_in", 300);
            if (string.IsNullOrEmpty(access) || string.IsNullOrEmpty(idToken))
                return new { ok = false, state = "TOKEN_RESPONSE_INCOMPLETE" };

            using var validation = await Http.PostAsJsonAsync(Api + "/v1/auth/validate", new { id_token = idToken, access_token = access, nonce });
            if (!validation.IsSuccessStatusCode)
                return new { ok = false, state = validation.StatusCode == HttpStatusCode.ServiceUnavailable ? "IDENTITY_UNAVAILABLE" : "IDENTITY_REJECTED" };

            _accessToken = access;
            _accessExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(expiresIn, 30, 86400));
            _issuer = config.Issuer;
            _clientId = config.ClientId;
            _refreshToken = !string.IsNullOrEmpty(refresh) ? refresh : _refreshToken;
            _reauthRequired = false;
            if (!string.IsNullOrEmpty(_refreshToken))
                _tokenStore.Save(new ProtectedRefreshToken(_issuer, _clientId, _refreshToken));
            return new { ok = true, state = "AUTHENTICATED" };
        }
        catch (OperationCanceledException)
        {
            return new { ok = false, state = "LOGIN_TIMEOUT_OR_CANCELLED" };
        }
        catch
        {
            return new { ok = false, state = "LOGIN_FAILED" };
        }
        finally { _gate.Release(); }
    }

    public async Task<object> LogoutAsync()
    {
        await _gate.WaitAsync();
        try
        {
            var access = _accessToken;
            var refresh = _refreshToken;
            var config = await GetConfigAsync();
            var localSignedOut = string.IsNullOrEmpty(access);
            if (!string.IsNullOrEmpty(access))
            {
                using var response = await SendApiAsync(HttpMethod.Post, "/v1/auth/logout", null);
                localSignedOut = response.IsSuccessStatusCode;
            }
            var revoked = false;
            if (!string.IsNullOrEmpty(refresh) && config is not null && config.LoginSupported)
            {
                try
                {
                    var discovery = await DiscoverAsync(config);
                    if (!string.IsNullOrEmpty(discovery.RevocationEndpoint))
                    {
                        using var response = await Http.PostAsync(discovery.RevocationEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
                        {
                            ["token"] = refresh, ["token_type_hint"] = "refresh_token", ["client_id"] = config.ClientId,
                        }));
                        revoked = response.IsSuccessStatusCode;
                    }
                }
                catch { /* Local API revocation remains authoritative when provider revocation is unavailable. */ }
            }
            ClearInMemory();
            _tokenStore.Delete();
            return new { ok = localSignedOut, state = localSignedOut ? "SIGNED_OUT" : "LOCAL_SIGNOUT_PENDING", provider_revoked = revoked };
        }
        catch
        {
            ClearInMemory();
            _tokenStore.Delete();
            return new { ok = false, state = "SIGNED_OUT_LOCALLY_PROVIDER_STATUS_UNKNOWN", provider_revoked = false };
        }
        finally { _gate.Release(); }
    }

    public async Task<JsonElement> ExecuteCustomerOperationAsync(string operation)
    {
        var (method, path) = operation switch
        {
            "mailboxes" => (HttpMethod.Get, "/v1/mailboxes"),
            "connect-gmail" => (HttpMethod.Post, "/v1/mailboxes/gmail-primary/connect"),
            "disconnect-gmail" => (HttpMethod.Delete, "/v1/mailboxes/gmail-primary"),
            "sync-status" => (HttpMethod.Get, "/v1/sync/status"),
            "sync-now" => (HttpMethod.Post, "/v1/sync"),
            _ => throw new InvalidOperationException("Customer API operation is not allowlisted."),
        };
        using var response = await SendApiAsync(method, path, null);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    private async Task RestoreAsync(CustomerOidcConfig config)
    {
        if (!string.IsNullOrEmpty(_accessToken) && _accessExpiresAt > DateTimeOffset.UtcNow.AddMinutes(1)) return;
        if (_refreshToken is null)
        {
            try
            {
                var stored = _tokenStore.Load();
                if (stored is not null && stored.Issuer == config.Issuer && stored.ClientId == config.ClientId)
                {
                    _refreshToken = stored.RefreshToken;
                    _issuer = stored.Issuer;
                    _clientId = stored.ClientId;
                }
                else if (stored is not null) _tokenStore.Delete();
            }
            catch { _reauthRequired = true; _tokenStore.Delete(); }
        }
        if (string.IsNullOrEmpty(_refreshToken)) return;
        try
        {
            var discovery = await DiscoverAsync(config);
            using var response = await Http.PostAsync(discovery.TokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token", ["client_id"] = config.ClientId, ["refresh_token"] = _refreshToken,
            }));
            if (!response.IsSuccessStatusCode)
            {
                ClearInMemory(); _tokenStore.Delete(); _reauthRequired = true; return;
            }
            using var token = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            _accessToken = ReadString(token.RootElement, "access_token");
            var rotatedRefresh = ReadString(token.RootElement, "refresh_token");
            if (!string.IsNullOrEmpty(rotatedRefresh)) _refreshToken = rotatedRefresh;
            _accessExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(ReadInt(token.RootElement, "expires_in", 300), 30, 86400));
            _issuer = config.Issuer; _clientId = config.ClientId;
            if (string.IsNullOrEmpty(_accessToken)) throw new InvalidDataException();
            _tokenStore.Save(new ProtectedRefreshToken(_issuer, _clientId, _refreshToken));
            _reauthRequired = false;
        }
        catch { ClearInMemory(); _reauthRequired = true; }
    }

    private async Task<HttpResponseMessage> SendApiAsync(HttpMethod method, string path, HttpContent? content)
    {
        var config = await GetConfigAsync();
        if (config is null || !config.LoginSupported)
            throw new InvalidOperationException("Customer OIDC is not configured.");
        await RestoreAsync(config);
        if (string.IsNullOrEmpty(_accessToken)) throw new UnauthorizedAccessException("Customer sign-in is required.");
        var request = new HttpRequestMessage(method, Api + path) { Content = content };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _accessToken);
        var response = await Http.SendAsync(request);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            response.Dispose(); ClearInMemory(); _tokenStore.Delete(); _reauthRequired = true;
            throw new UnauthorizedAccessException("Customer session expired or was revoked.");
        }
        return response;
    }

    private static async Task<CustomerOidcConfig?> GetConfigAsync()
    {
        try
        {
            using var response = await Http.GetAsync(Api + "/v1/auth/config");
            if (!response.IsSuccessStatusCode) return null;
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root = json.RootElement;
            return new CustomerOidcConfig(
                ReadString(root, "issuer"), ReadString(root, "client_id"), ReadString(root, "audience"),
                ReadString(root, "authorization_endpoint"), ReadString(root, "token_endpoint"),
                ReadString(root, "revocation_endpoint"), ReadString(root, "discovery_url"),
                root.TryGetProperty("login_supported", out var enabled) && enabled.ValueKind == JsonValueKind.True,
                root.TryGetProperty("test_mode", out var test) && test.ValueKind == JsonValueKind.True);
        }
        catch { return null; }
    }

    private static async Task<OidcDiscovery> DiscoverAsync(CustomerOidcConfig config)
    {
        var uri = new Uri(config.DiscoveryUrl ?? throw new InvalidDataException());
        if (uri.Scheme != "https" && !(config.TestMode && uri.IsLoopback && uri.Scheme == "http")) throw new InvalidDataException();
        using var response = await Http.GetAsync(uri);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = document.RootElement;
        var issuer = ReadString(root, "issuer");
        var authorization = config.AuthorizationEndpoint ?? ReadString(root, "authorization_endpoint");
        var token = config.TokenEndpoint ?? ReadString(root, "token_endpoint");
        var revocation = config.RevocationEndpoint ?? ReadString(root, "revocation_endpoint");
        if (issuer != config.Issuer || !ValidEndpoint(authorization, config.TestMode) || !ValidEndpoint(token, config.TestMode) || (!string.IsNullOrEmpty(revocation) && !ValidEndpoint(revocation, config.TestMode)))
            throw new InvalidDataException("OIDC discovery metadata does not match the configured issuer.");
        return new OidcDiscovery(authorization!, token!, revocation);
    }

    private static bool ValidEndpoint(string? value, bool testMode)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
            (uri.Scheme == "https" || (testMode && uri.Scheme == "http" && uri.IsLoopback));
    }

    private static async Task<(string RedirectUri, string Code, string State, string Nonce, string Verifier)> AuthorizeInSystemBrowserAsync(OidcDiscovery discovery, CustomerOidcConfig config)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(48));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var state = Base64Url(RandomNumberGenerator.GetBytes(32));
        var nonce = Base64Url(RandomNumberGenerator.GetBytes(32));
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        var number = ((IPEndPoint)port.LocalEndpoint).Port;
        port.Stop();
        var redirect = $"http://127.0.0.1:{number}/oauth2callback/";
        using var listener = new HttpListener();
        listener.Prefixes.Add(redirect);
        listener.Start();
        var query = new Dictionary<string, string>
        {
            ["client_id"] = config.ClientId, ["redirect_uri"] = redirect,
            ["response_type"] = "code", ["scope"] = "openid profile offline_access",
            ["state"] = state, ["nonce"] = nonce, ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        };
        var authUri = discovery.AuthorizationEndpoint + "?" + string.Join("&", query.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        Process.Start(new ProcessStartInfo(authUri) { UseShellExecute = true });
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var context = await listener.GetContextAsync().WaitAsync(timeout.Token);
        try
        {
            if (context.Request.RemoteEndPoint is null || !IPAddress.IsLoopback(context.Request.RemoteEndPoint.Address) || context.Request.Url?.AbsolutePath != "/oauth2callback/")
                throw new InvalidDataException("OIDC callback is invalid.");
            var actualState = context.Request.QueryString["state"] ?? "";
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(actualState), Encoding.UTF8.GetBytes(state)))
                throw new InvalidDataException("OIDC callback state is invalid.");
            var code = context.Request.QueryString["code"];
            if (string.IsNullOrEmpty(code) || code.Length > 8192) throw new InvalidDataException("OIDC authorization code is missing.");
            if (!string.IsNullOrEmpty(context.Request.QueryString["error"])) throw new OperationCanceledException("Authorization was denied.");
            var page = Encoding.UTF8.GetBytes("<!doctype html><meta charset=utf-8><title>MailTrace</title><p>MailTrace sign-in complete. You can close this tab.</p>");
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers["Cache-Control"] = "no-store";
            context.Response.ContentLength64 = page.Length;
            await context.Response.OutputStream.WriteAsync(page);
            return (redirect, code, state, nonce, verifier);
        }
        finally { context.Response.Close(); }
    }

    private void ClearInMemory()
    {
        _accessToken = null; _refreshToken = null; _issuer = null; _clientId = null; _accessExpiresAt = default;
    }

    private static string Base64Url(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string? ReadString(JsonElement element, string property) => element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static int ReadInt(JsonElement element, string property, int fallback) => element.TryGetProperty(property, out var value) && value.TryGetInt32(out var parsed) ? parsed : fallback;

    private sealed record CustomerOidcConfig(string? Issuer, string? ClientId, string? Audience, string? AuthorizationEndpoint, string? TokenEndpoint, string? RevocationEndpoint, string? DiscoveryUrl, bool LoginSupported, bool TestMode);
    private sealed record OidcDiscovery(string AuthorizationEndpoint, string TokenEndpoint, string? RevocationEndpoint);
}

internal sealed record ProtectedRefreshToken(string? Issuer, string? ClientId, string RefreshToken);

internal sealed class DpapiRefreshTokenStore
{
    private readonly string _path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MailTrace", "customer", "oidc.dpapi");

    public void Save(ProtectedRefreshToken token)
    {
        var json = JsonSerializer.SerializeToUtf8Bytes(token);
        var protectedBytes = Transform(json, decrypt: false);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var temporary = _path + ".new";
        File.WriteAllBytes(temporary, protectedBytes);
        File.Move(temporary, _path, overwrite: true);
    }

    public ProtectedRefreshToken? Load()
    {
        if (!File.Exists(_path)) return null;
        var clear = Transform(File.ReadAllBytes(_path), decrypt: true);
        return JsonSerializer.Deserialize<ProtectedRefreshToken>(clear);
    }

    public void Delete()
    {
        try { File.Delete(_path); } catch (FileNotFoundException) { }
    }

    private static byte[] Transform(byte[] input, bool decrypt)
    {
        if (!OperatingSystem.IsWindows() || input.Length == 0) throw new CryptographicException("Windows DPAPI is unavailable.");
        var sourceMemory = Marshal.AllocHGlobal(input.Length);
        Marshal.Copy(input, 0, sourceMemory, input.Length);
        var source = new DataBlob { Length = input.Length, Data = sourceMemory };
        try
        {
            DataBlob output;
            var ok = decrypt ? CryptUnprotectData(ref source, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptProtectData(ref source, "MailTrace Customer OIDC", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new CryptographicException("Windows could not access the protected customer token store.");
            try
            {
                var bytes = new byte[output.Length];
                Marshal.Copy(output.Data, bytes, 0, output.Length);
                return bytes;
            }
            finally { LocalFree(output.Data); }
        }
        finally { Marshal.FreeHGlobal(sourceMemory); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptProtectData")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptProtectData(ref DataBlob input, string description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true, EntryPoint = "CryptUnprotectData")]
    [return: MarshalAs(UnmanagedType.Bool)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr memory);
}
