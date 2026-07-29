#nullable enable
using System.Text.Json.Serialization;

namespace SwmSdk;

public sealed class EnrollmentTicketRequest
{
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;
}

public sealed class EnrollmentTicketResponse
{
    [JsonPropertyName("ticket")]
    public string Ticket { get; set; } = string.Empty;
    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;
}
