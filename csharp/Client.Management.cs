using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SwmSdk;

public partial class Client
{
    private static async Task<T> DeserializeDataAsync<T>(HttpResponseMessage response, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default)
    {
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
        return await JsonDefaults.DeserializeAsync(response.Content, typeInfo, cancellationToken).ConfigureAwait(false);
    }

    private Task<HttpResponseMessage> DoAuthJsonAsync(HttpMethod method, string path, HttpContent? payload = null, Dictionary<string, string?>? query = null, CancellationToken cancellationToken = default)
    {
        return DoAuthRequestAsync(method, path, query, payload, cancellationToken);
    }

    public async Task<AppDto> GetAppAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.AppResponse, cancellationToken).ConfigureAwait(false);
        return payload.App;
    }

    public async Task<AppDto> UpdateAppAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/apps/{appId}", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.AppResponse, cancellationToken).ConfigureAwait(false);
        return payload.App;
    }

    public async Task<List<ChannelDto>> ListChannelsAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/channels", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseChannelDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<ChannelDto> CreateChannelAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/apps/{appId}/channels", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ChannelResponse, cancellationToken).ConfigureAwait(false);
        return payload.Channel;
    }

    public async Task<List<AppMemberDto>> ListAppMembersAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/members", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseAppMemberDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<DynamicDto> AddAppMemberAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/apps/{appId}/members", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync(response, SwmJsonContext.Default.DynamicDto, cancellationToken).ConfigureAwait(false);
    }

    public async Task<List<ReleaseDto>> ListReleasesAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/releases", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseReleaseDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<ReleaseDto> CreateReleaseAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/apps/{appId}/releases", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseResponse, cancellationToken).ConfigureAwait(false);
        return payload.Release;
    }

    public async Task<ReleaseDto> UpdateReleaseAsync(string releaseId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/releases/{releaseId}", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseResponse, cancellationToken).ConfigureAwait(false);
        return payload.Release;
    }

    public async Task DeleteReleaseAsync(string releaseId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Delete, $"/api/releases/{releaseId}", cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public Task SubmitReleaseAsync(string releaseId, string note, CancellationToken cancellationToken = default) => ReviewReleaseActionAsync(releaseId, "submit", note, cancellationToken);
    public Task ApproveReleaseAsync(string releaseId, string note, CancellationToken cancellationToken = default) => ReviewReleaseActionAsync(releaseId, "approve", note, cancellationToken);
    public Task RejectReleaseAsync(string releaseId, string note, CancellationToken cancellationToken = default) => ReviewReleaseActionAsync(releaseId, "reject", note, cancellationToken);

    private async Task ReviewReleaseActionAsync(string releaseId, string action, string note, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(new ReviewNoteRequest { Note = note }, SwmJsonContext.Default.ReviewNoteRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/releases/{releaseId}/{action}", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ReleaseChannelDto> PublishReleaseAsync(string releaseId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/releases/{releaseId}/publish", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseChannelResponse, cancellationToken).ConfigureAwait(false);
        return payload.ReleaseChannel;
    }

    public async Task<ReleaseChannelDto> RollbackReleaseAsync(string releaseId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/releases/{releaseId}/rollback", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseChannelResponse, cancellationToken).ConfigureAwait(false);
        return payload.ReleaseChannel;
    }

    public async Task RevokeReleaseAsync(string releaseId, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(new DynamicRequest(), SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/releases/{releaseId}/revoke", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ArtifactDto> UploadArtifactAsync(string releaseId, UploadArtifactOptions options, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(options.Platform) || string.IsNullOrWhiteSpace(options.Arch) || string.IsNullOrWhiteSpace(options.FileType))
        {
            throw new SwmValidationException(400, null, "platform, arch, file_type required");
        }
        if (string.IsNullOrWhiteSpace(options.FilePath) || !File.Exists(options.FilePath))
        {
            throw new SwmValidationException(400, null, "file_path required");
        }

        if (string.IsNullOrWhiteSpace(AuthToken))
        {
            throw new SwmUnauthorizedException(401, null, "auth token required, call SetAuthToken first");
        }

        using var form = new MultipartFormDataContent();
        using var file = File.OpenRead(options.FilePath);
        form.Add(new StringContent(options.Platform), "platform");
        form.Add(new StringContent(options.Arch), "arch");
        form.Add(new StringContent(options.FileType), "file_type");
        if (!string.IsNullOrWhiteSpace(options.Signature))
        {
            form.Add(new StringContent(options.Signature!), "signature");
        }
        if (options.Replace)
        {
            form.Add(new StringContent("true"), "replace");
        }
        var fileContent = new StreamContent(file);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "file", Path.GetFileName(options.FilePath));

        using var response = await DoAuthRequestAsync(HttpMethod.Post, $"/api/releases/{releaseId}/artifacts", body: form, cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
        var root = await JsonDefaults.DeserializeAsync(response.Content, SwmJsonContext.Default.DictionaryStringArtifactDto, cancellationToken).ConfigureAwait(false);
        if (!root.TryGetValue("artifact", out var artifact) || artifact == null)
        {
            throw new SwmApiException(0, null, "artifact missing in response");
        }
        return artifact;
    }

    public async Task<List<ArtifactDto>> ListArtifactsAsync(string releaseId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/releases/{releaseId}/artifacts", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseArtifactDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<string> GetArtifactDownloadUrlAsync(string artifactId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(AuthToken))
        {
            throw new SwmUnauthorizedException(401, null, "auth token required, call SetAuthToken first");
        }

        using var req = new HttpRequestMessage(HttpMethod.Get, $"{BaseUrl}/api/artifacts/{artifactId}/download");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);
        SignAuthRequest(req, Array.Empty<byte>(), AuthToken);
        using var client = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false
        });
        using var response = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

        var statusCode = (int)response.StatusCode;
        if (statusCode >= 300 && statusCode < 400)
        {
            var location = response.Headers.Location?.ToString();
            if (string.IsNullOrWhiteSpace(location))
            {
                throw new SwmApiException(statusCode, null, "missing redirect location");
            }
            return location!;
        }

        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
        throw new SwmApiException(statusCode, null, $"unexpected status {(HttpStatusCode)statusCode}, expected redirect");
    }

    public async Task<List<ReleaseChannelDto>> ListReleaseChannelsAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/release-channels", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseReleaseChannelDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<ReleaseChannelDto> CreateReleaseChannelAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/apps/{appId}/release-channels", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseChannelResponse, cancellationToken).ConfigureAwait(false);
        return payload.ReleaseChannel;
    }

    public async Task<ReleaseChannelDto> UpdateReleaseChannelAsync(string releaseChannelId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/release-channels/{releaseChannelId}", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseChannelResponse, cancellationToken).ConfigureAwait(false);
        return payload.ReleaseChannel;
    }

    public async Task<DynamicDto> GetReleaseChannelMetricsAsync(string appId, string releaseChannelId, string? from = null, string? to = null, CancellationToken cancellationToken = default)
    {
        var query = new Dictionary<string, string?>
        {
            ["from"] = from,
            ["to"] = to
        };
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/release-channels/{releaseChannelId}/metrics", query: query, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync(response, SwmJsonContext.Default.DynamicDto, cancellationToken).ConfigureAwait(false);
    }

    public async Task<JsonElement> GetAppRegionRulesAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/region-rules", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.AppRegionRulesResponse, cancellationToken).ConfigureAwait(false);
        return payload.RegionRules;
    }

    public async Task<JsonElement> UpdateAppRegionRulesAsync(string appId, JsonElement rules, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(new RegionRulesUpdateRequest { RegionRules = rules }, SwmJsonContext.Default.RegionRulesUpdateRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/apps/{appId}/region-rules", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.AppRegionRulesResponse, cancellationToken).ConfigureAwait(false);
        return payload.RegionRules;
    }

    public async Task<DynamicDto> ListGeoRegionsAsync(CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, "/api/geo/regions", cancellationToken: cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync(response, SwmJsonContext.Default.DynamicDto, cancellationToken).ConfigureAwait(false);
    }

    public async Task<DynamicDto> ResolveGeoAsync(string ip, CancellationToken cancellationToken = default)
    {
        var query = new Dictionary<string, string?> { ["ip"] = ip };
        using var response = await DoAuthJsonAsync(HttpMethod.Get, "/api/geo/resolve", query: query, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync(response, SwmJsonContext.Default.DynamicDto, cancellationToken).ConfigureAwait(false);
    }

    public async Task<List<ReleaseTemplateDto>> ListReleaseTemplatesAsync(CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, "/api/release-templates", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseReleaseTemplateDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<ReleaseTemplateDto> CreateReleaseTemplateAsync(DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, "/api/release-templates", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.TemplateResponse, cancellationToken).ConfigureAwait(false);
        return payload.Template;
    }

    public async Task<ReleaseTemplateDto> UpdateReleaseTemplateAsync(string templateId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/release-templates/{templateId}", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.TemplateResponse, cancellationToken).ConfigureAwait(false);
        return payload.Template;
    }

    public async Task DeleteReleaseTemplateAsync(string templateId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Delete, $"/api/release-templates/{templateId}", cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ReleaseDto> SetReleaseTemplateAsync(string releaseId, string templateId, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(new SetTemplateRequest { TemplateId = templateId }, SwmJsonContext.Default.SetTemplateRequest);
        using var response = await DoAuthJsonAsync(PatchMethod, $"/api/releases/{releaseId}/template", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ReleaseResponse, cancellationToken).ConfigureAwait(false);
        return payload.Release;
    }

    public async Task<List<AppSecretDto>> ListAppSecretsAsync(string appId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Get, $"/api/apps/{appId}/app-secrets", cancellationToken: cancellationToken).ConfigureAwait(false);
        var payload = await DeserializeDataAsync(response, SwmJsonContext.Default.ListResponseAppSecretDto, cancellationToken).ConfigureAwait(false);
        return payload.Items;
    }

    public async Task<AppSecretCreateResponse> CreateAppSecretAsync(string appId, DynamicRequest request, CancellationToken cancellationToken = default)
    {
        var body = JsonDefaults.ToJsonContent(request, SwmJsonContext.Default.DynamicRequest);
        using var response = await DoAuthJsonAsync(HttpMethod.Post, $"/api/apps/{appId}/app-secrets", body, cancellationToken: cancellationToken).ConfigureAwait(false);
        return await DeserializeDataAsync(response, SwmJsonContext.Default.AppSecretCreateResponse, cancellationToken).ConfigureAwait(false);
    }

    public async Task RevokeAppSecretAsync(string keyId, CancellationToken cancellationToken = default)
    {
        using var response = await DoAuthJsonAsync(HttpMethod.Delete, $"/api/app-secrets/{keyId}", cancellationToken: cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
    }
    public Task<string> GetArtifactDownloadURLAsync(string artifactId, CancellationToken cancellationToken = default) => GetArtifactDownloadUrlAsync(artifactId, cancellationToken);
}
