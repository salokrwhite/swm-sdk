using System.Text.Json;
using System.Text.Json.Serialization;

namespace SwmSdk;

[JsonSourceGenerationOptions(
    PropertyNameCaseInsensitive = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
)]
[JsonSerializable(typeof(UpdateCheckRequest))]
[JsonSerializable(typeof(UpdateCheckResponse))]
[JsonSerializable(typeof(EventIngestItem))]
[JsonSerializable(typeof(EventBatchRequest))]
[JsonSerializable(typeof(HeartbeatRequest))]
[JsonSerializable(typeof(UpdatePushEvent))]
[JsonSerializable(typeof(DynamicRequest))]
[JsonSerializable(typeof(DynamicDto))]
[JsonSerializable(typeof(AppDto))]
[JsonSerializable(typeof(ChannelDto))]
[JsonSerializable(typeof(ReleaseDto))]
[JsonSerializable(typeof(ReleaseChannelDto))]
[JsonSerializable(typeof(ArtifactDto))]
[JsonSerializable(typeof(ReleaseTemplateDto))]
[JsonSerializable(typeof(AppSecretDto))]
[JsonSerializable(typeof(AppMemberDto))]
[JsonSerializable(typeof(ListResponse<ChannelDto>))]
[JsonSerializable(typeof(ListResponse<AppMemberDto>))]
[JsonSerializable(typeof(ListResponse<ReleaseDto>))]
[JsonSerializable(typeof(ListResponse<ArtifactDto>))]
[JsonSerializable(typeof(ListResponse<ReleaseChannelDto>))]
[JsonSerializable(typeof(ListResponse<ReleaseTemplateDto>))]
[JsonSerializable(typeof(ListResponse<AppSecretDto>))]
[JsonSerializable(typeof(AppResponse))]
[JsonSerializable(typeof(ChannelResponse))]
[JsonSerializable(typeof(ReleaseResponse))]
[JsonSerializable(typeof(ReleaseChannelResponse))]
[JsonSerializable(typeof(TemplateResponse))]
[JsonSerializable(typeof(AppSecretCreateResponse))]
[JsonSerializable(typeof(AppRegionRulesResponse))]
[JsonSerializable(typeof(ReviewNoteRequest))]
[JsonSerializable(typeof(SetTemplateRequest))]
[JsonSerializable(typeof(RegionRulesUpdateRequest))]
[JsonSerializable(typeof(Dictionary<string, ArtifactDto>))]
[JsonSerializable(typeof(Dictionary<string, JsonElement>))]
internal partial class SwmJsonContext : JsonSerializerContext
{
}
