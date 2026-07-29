using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SwmSdk;

public partial class Client
{
    private const string SignHeaderAppId = "X-App-Id";
    private const string SignHeaderTimestamp = "X-Timestamp";
    private const string SignHeaderNonce = "X-Nonce";
    private const string SignHeaderSignature = "X-Signature";
    private const string SignHeaderVersion = "X-Sign-Version";
    private const string SignVersion = "v1";
    private const string AuthzCapabilityHeader = "X-Authz-Capability";
	private const string ClientReleaseIdHeader = "X-Client-Release-Id";
	private const string ClientVersionHeader = "X-Client-Version";
	private const string ClientVersionCodeHeader = "X-Client-Version-Code";
	private const string SwmSessionHeader = "X-SWM-Session";
	private const string SwmDpopHeader = "X-SWM-DPoP";

    private static string QueryEscapeRfc3986(string value)
    {
        return Uri.EscapeDataString(value)
            .Replace("+", "%20")
            .Replace("*", "%2A");
    }

    private static List<KeyValuePair<string, string>> ParseQueryPairs(string? query)
    {
        var pairs = new List<KeyValuePair<string, string>>();
        if (string.IsNullOrWhiteSpace(query))
        {
            return pairs;
        }
        var raw = query![0] == '?' ? query.Substring(1) : query;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return pairs;
        }
        var items = raw.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var item in items)
        {
            var idx = item.IndexOf('=');
            var key = idx >= 0 ? item.Substring(0, idx) : item;
            var val = idx >= 0 ? item.Substring(idx + 1) : string.Empty;
            key = Uri.UnescapeDataString(key.Replace("+", "%20"));
            val = Uri.UnescapeDataString(val.Replace("+", "%20"));
            pairs.Add(new KeyValuePair<string, string>(key, val));
        }
        return pairs;
    }

    private static string BuildCanonicalQuery(Uri uri)
    {
        var pairs = ParseQueryPairs(uri.Query);
        if (pairs.Count == 0)
        {
            return string.Empty;
        }
        pairs.Sort((a, b) =>
        {
            var cmp = string.CompareOrdinal(a.Key, b.Key);
            if (cmp != 0)
            {
                return cmp;
            }
            return string.CompareOrdinal(a.Value, b.Value);
        });
        return string.Join("&", pairs.Select(p => $"{QueryEscapeRfc3986(p.Key)}={QueryEscapeRfc3986(p.Value)}"));
    }

    private static string SHA256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        return HexLower(sha.ComputeHash(data));
    }

    private static string HmacSHA256Hex(string key, string data)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        var sig = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return HexLower(sig);
    }

    private static string ExtractJwtSubject(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return string.Empty;
        }
        var parts = token.Split('.');
        if (parts.Length < 2 || string.IsNullOrWhiteSpace(parts[1]))
        {
            return string.Empty;
        }
        try
        {
            var segment = parts[1]
                .Replace('-', '+')
                .Replace('_', '/');
            switch (segment.Length % 4)
            {
                case 2:
                    segment += "==";
                    break;
                case 3:
                    segment += "=";
                    break;
            }
            var bytes = Convert.FromBase64String(segment);
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String)
            {
                return sub.GetString()?.Trim() ?? string.Empty;
            }
            if (doc.RootElement.TryGetProperty("uid", out var uid) && uid.ValueKind == JsonValueKind.String)
            {
                return uid.GetString()?.Trim() ?? string.Empty;
            }
        }
        catch
        {
            // ignore
        }
        return string.Empty;
    }

    private static string BuildCanonical(HttpRequestMessage request, byte[] bodyBytes, long timestamp, string nonce, string identity)
    {
        var uri = request.RequestUri ?? new Uri("http://localhost/");
        return string.Join("\n", new[]
        {
            request.Method.Method.ToUpperInvariant(),
            uri.AbsolutePath,
            BuildCanonicalQuery(uri),
            SHA256Hex(bodyBytes),
            timestamp.ToString(),
            nonce,
            identity
        });
    }

    private static void SetRequestBindingHeaders(HttpRequestMessage request, long timestamp, string nonce)
    {
        request.Headers.TryAddWithoutValidation(SignHeaderTimestamp, timestamp.ToString());
        request.Headers.TryAddWithoutValidation(SignHeaderNonce, nonce);
    }

    private static void SetAuthSignatureHeaders(HttpRequestMessage request, long timestamp, string nonce, string signature)
    {
		SetRequestBindingHeaders(request, timestamp, nonce);
        request.Headers.TryAddWithoutValidation(SignHeaderSignature, signature);
        request.Headers.TryAddWithoutValidation(SignHeaderVersion, SignVersion);
    }

    private string SignClientRequest(HttpRequestMessage request, byte[] bodyBytes)
    {
		if (AuthzV3Required)
		{
			var profile = SecurityProfile!;
			var native = NativeSecurityContext ?? throw InvalidAuthz("MySwm native security context is required for Authz v3");
			var operation = ResolveNativeOperation(request);
			string v3Nonce;
			if (operation == MySwmOperation.UpdateCheck)
			{
				var auth = native.CreateUpdateAuth(bodyBytes);
				v3Nonce = auth.Nonce;
				SetRequestBindingHeaders(request, auth.Timestamp, auth.Nonce);
			}
			else
			{
				v3Nonce = Guid.NewGuid().ToString();
				SetRequestBindingHeaders(request, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), v3Nonce);
			}
			request.Headers.TryAddWithoutValidation(SignHeaderAppId, AppId);
			request.Headers.TryAddWithoutValidation(AuthzCapabilityHeader, profile.Protocol);
			request.Headers.TryAddWithoutValidation(ClientReleaseIdHeader, profile.ReleaseId);
			request.Headers.TryAddWithoutValidation(ClientVersionHeader, profile.Version);
			request.Headers.TryAddWithoutValidation(ClientVersionCodeHeader, profile.VersionCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
			if (!string.IsNullOrWhiteSpace(SessionToken)) request.Headers.TryAddWithoutValidation(SwmSessionHeader, SessionToken);
			var resourceId = operation == MySwmOperation.UpdateStream ? request.RequestUri?.AbsoluteUri : null;
			request.Headers.TryAddWithoutValidation(SwmDpopHeader, native.CreateProof(operation, bodyBytes, resourceId));
			return v3Nonce;
		}
		throw InvalidAuthz("Authz v3 security profile is required");
    }

	private static MySwmOperation ResolveNativeOperation(HttpRequestMessage request)
	{
		var path = request.RequestUri?.AbsolutePath ?? string.Empty;
		return path switch
		{
			"/api/client/update-check" => MySwmOperation.UpdateCheck,
			"/api/client/heartbeat" => MySwmOperation.Heartbeat,
			"/api/client/events" => MySwmOperation.Events,
			"/api/client/feedback" => MySwmOperation.Feedback,
			"/api/client/enrollment-ticket" => MySwmOperation.EnrollmentTicket,
			"/api/client/updates/stream" => MySwmOperation.UpdateStream,
			_ => throw InvalidAuthz("request path is not allowed by MySwm")
		};
	}

    private void SignAuthRequest(HttpRequestMessage request, byte[] bodyBytes, string rawToken)
    {
        var sub = ExtractJwtSubject(rawToken);
        if (string.IsNullOrWhiteSpace(sub))
        {
            throw new SwmUnauthorizedException(401, null, "invalid auth token subject");
        }
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var nonce = Guid.NewGuid().ToString();
        var canonical = BuildCanonical(request, bodyBytes, timestamp, nonce, sub);
        var signature = HmacSHA256Hex(rawToken, canonical);
        SetAuthSignatureHeaders(request, timestamp, nonce, signature);
    }
}
