#nullable enable
using System.Text;
using System.Text.Json;

namespace SwmSdk;

public partial class Client
{
    public async Task<EnrollmentTicketResponse> RequestEnrollmentTicketAsync(
        string audience,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(DeviceId))
        {
            throw new SwmValidationException(400, null, "device_id required");
        }
		RequireV3SecurityProfile();
		if (string.IsNullOrWhiteSpace(SessionToken) ||
            SessionExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            throw InvalidAuthz("authorization session required for enrollment");
        }

        var payload = new EnrollmentTicketRequest { Audience = audience?.Trim() ?? string.Empty };
        var (response, nonce) = await DoRequestCapturingNonceAsync(
            HttpMethod.Post,
            "/api/client/enrollment-ticket",
            JsonDefaults.ToJsonContent(payload, SwmJsonContext.Default.EnrollmentTicketRequest),
            cancellationToken).ConfigureAwait(false);
        using (response)
        {
            await SwmErrorParser.ThrowIfErrorAsync(response, cancellationToken).ConfigureAwait(false);
            var raw = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
			var carrier = JsonSerializer.Deserialize(raw, SwmJsonContext.Default.AuthzV3Carrier)
                ?? throw InvalidAuthz("signed enrollment response missing");
            var dataRaw = Encoding.UTF8.GetBytes(carrier.Data.GetRawText());
			VerifyAuthzV3OrThrow(carrier.Authz, nonce, dataRaw);
            return JsonSerializer.Deserialize(dataRaw, SwmJsonContext.Default.EnrollmentTicketResponse)
                ?? throw InvalidAuthz("enrollment ticket data missing");
        }
    }
}
