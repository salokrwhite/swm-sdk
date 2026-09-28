namespace SwmSdk.Internal;

internal enum SwmOperationClass
{
    TrustedTimeSync,
    OnlineKeyManifest,
    UpdateCheck,
    Heartbeat,
    OperationAuthorization,
    OperationGrantConsume,
    Events,
    Feedback,
    EnrollmentTicket,
    DeviceKeyRotation,
    Download,
    UpdateStream,
    FirmwareIdentity,
    DebugProtocol,
    DebugStream
}

internal readonly record struct RequestPolicy(
    int TimeoutMilliseconds,
    int Retries,
    int BackoffMilliseconds,
    int BackoffMaxMilliseconds,
    int DeadlineMilliseconds);

internal static class RequestPolicies
{
    public static RequestPolicy Resolve(SwmOperationClass operation)
    {
        return operation switch
        {
            SwmOperationClass.TrustedTimeSync => new(10000, 2, 1000, 4000, 40000),
            SwmOperationClass.OnlineKeyManifest => new(10000, 2, 1000, 4000, 40000),
            SwmOperationClass.UpdateCheck => new(15000, 2, 1500, 6000, 60000),
            SwmOperationClass.Heartbeat => new(8000, 2, 1000, 4000, 30000),
            SwmOperationClass.OperationAuthorization => new(10000, 2, 1000, 4000, 36000),
            SwmOperationClass.OperationGrantConsume => new(10000, 1, 1000, 2000, 24000),
            SwmOperationClass.Events => new(8000, 1, 1000, 2000, 20000),
            SwmOperationClass.Feedback => new(10000, 1, 1000, 2000, 24000),
            SwmOperationClass.EnrollmentTicket => new(10000, 1, 1000, 2000, 24000),
            SwmOperationClass.DeviceKeyRotation => new(10000, 1, 1000, 2000, 24000),
            SwmOperationClass.Download => new(30000, 2, 2000, 8000, 0),
            SwmOperationClass.UpdateStream => new(30000, 0, 0, 0, 0),
            SwmOperationClass.FirmwareIdentity => new(8000, 1, 500, 1000, 20000),
            SwmOperationClass.DebugProtocol => new(8000, 1, 500, 1000, 20000),
            SwmOperationClass.DebugStream => new(8000, 1, 500, 1000, 20000),
            _ => new(8000, 1, 1000, 2000, 20000)
        };
    }

    public static int CycleRetryDelayMilliseconds(SwmOperationClass operation, int attempt)
    {
        var delays = operation switch
        {
            SwmOperationClass.Heartbeat => new[] { 5000, 10000, 20000, 30000 },
            SwmOperationClass.UpdateStream => new[] { 1500, 3000, 6000, 20000 },
            _ => Array.Empty<int>()
        };
        if (delays.Length == 0)
        {
            return 0;
        }
        return delays[Math.Min(Math.Max(attempt, 0), delays.Length - 1)];
    }
}
