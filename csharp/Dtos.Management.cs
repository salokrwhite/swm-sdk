using System.Text.Json;
using System.Text.Json.Serialization;

namespace SwmSdk;

public class DynamicRequest
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Properties { get; set; } = new();
}

public class DynamicDto
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Properties { get; set; }
}

public sealed class AppDto : DynamicDto { }
public sealed class ChannelDto : DynamicDto { }
public sealed class ReleaseDto : DynamicDto { }
public sealed class ReleaseChannelDto : DynamicDto { }
public sealed class ArtifactDto : DynamicDto { }
public sealed class ReleaseTemplateDto : DynamicDto { }
public sealed class AppSecretDto : DynamicDto { }
public sealed class AppMemberDto : DynamicDto { }

public sealed class ListResponse<T>
{
    [JsonPropertyName("items")]
    public List<T> Items { get; set; } = new();
}

public sealed class AppResponse
{
    [JsonPropertyName("app")]
    public AppDto App { get; set; } = new();
}

public sealed class ChannelResponse
{
    [JsonPropertyName("channel")]
    public ChannelDto Channel { get; set; } = new();
}

public sealed class ReleaseResponse
{
    [JsonPropertyName("release")]
    public ReleaseDto Release { get; set; } = new();
}

public sealed class ReleaseChannelResponse
{
    [JsonPropertyName("release_channel")]
    public ReleaseChannelDto ReleaseChannel { get; set; } = new();
}

public sealed class TemplateResponse
{
    [JsonPropertyName("template")]
    public ReleaseTemplateDto Template { get; set; } = new();
}

public sealed class AppSecretCreateResponse
{
    [JsonPropertyName("app_secret")]
    public string AppSecret { get; set; } = string.Empty;

    [JsonPropertyName("item")]
    public AppSecretDto Item { get; set; } = new();

    [JsonPropertyName("app_id")]
    public string? AppId { get; set; }
}

public sealed class AppRegionRulesResponse
{
    [JsonPropertyName("region_rules")]
    public JsonElement RegionRules { get; set; }
}

public sealed class UploadArtifactOptions
{
    public string Platform { get; set; } = string.Empty;
    public string Arch { get; set; } = string.Empty;
    public string FileType { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string? Signature { get; set; }
    public bool Replace { get; set; }
}

public sealed class ReviewNoteRequest
{
    [JsonPropertyName("note")]
    public string Note { get; set; } = string.Empty;
}

public sealed class SetTemplateRequest
{
    [JsonPropertyName("template_id")]
    public string TemplateId { get; set; } = string.Empty;
}

public sealed class RegionRulesUpdateRequest
{
    [JsonPropertyName("region_rules")]
    public JsonElement RegionRules { get; set; }
}
