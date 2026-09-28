using System.Diagnostics;

namespace SwmSdk.Internal;

internal sealed class TrustedClock
{
    private const long MaximumRoundTripMilliseconds = 5000;
    private const long MinimumServerTimeMilliseconds = 1577836800000;
    private const long MaximumServerTimeMilliseconds = 4102444800000;
    private readonly object _sync = new();
    private bool _initialized;
    private long _anchorUnixMilliseconds;
    private long _anchorTickMilliseconds;

    public bool IsInitialized
    {
        get
        {
            lock (_sync)
            {
                return _initialized;
            }
        }
    }

    public long NowUnixMilliseconds
    {
        get
        {
            lock (_sync)
            {
                return ReadAtLocked(TickMilliseconds());
            }
        }
    }

    public long NowUnixSeconds => NowUnixMilliseconds / 1000;

    public void SetAuthoritativeTime(
        long serverTimeMilliseconds,
        long requestStartedTickMilliseconds,
        long responseReceivedTickMilliseconds)
    {
        if (serverTimeMilliseconds < MinimumServerTimeMilliseconds ||
            serverTimeMilliseconds > MaximumServerTimeMilliseconds ||
            responseReceivedTickMilliseconds < requestStartedTickMilliseconds)
        {
            throw new SwmClockException("signed server time is outside the accepted range");
        }
        var roundTrip = responseReceivedTickMilliseconds - requestStartedTickMilliseconds;
        if (roundTrip > MaximumRoundTripMilliseconds)
        {
            throw new SwmClockException("signed server time round trip is too slow");
        }
        lock (_sync)
        {
            _anchorUnixMilliseconds = checked(serverTimeMilliseconds + roundTrip / 2);
            _anchorTickMilliseconds = responseReceivedTickMilliseconds;
            _initialized = true;
        }
    }

    public static long TickMilliseconds()
    {
        return (long)(Stopwatch.GetTimestamp() * (1000.0 / Stopwatch.Frequency));
    }

    private long ReadAtLocked(long tickMilliseconds)
    {
        if (!_initialized || tickMilliseconds < _anchorTickMilliseconds)
        {
            return 0;
        }
        return _anchorUnixMilliseconds + (tickMilliseconds - _anchorTickMilliseconds);
    }
}
