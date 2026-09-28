package com.swm.sdk.internal;

import com.swm.sdk.SwmException;

public final class TrustedClock {
    private static final long MAX_ROUND_TRIP_MS = 5000;
    private static final long MIN_SERVER_TIME_MS = 1_577_836_800_000L;
    private static final long MAX_SERVER_TIME_MS = 4_102_444_800_000L;

    private boolean initialized;
    private long anchorUnixMs;
    private long anchorTickMs;

    public synchronized boolean initialized() {
        return initialized;
    }

    public synchronized long nowUnixMs() {
        if (!initialized) {
            return 0;
        }
        var tick = System.nanoTime() / 1_000_000L;
        return tick < anchorTickMs ? 0 : anchorUnixMs + (tick - anchorTickMs);
    }

    public long nowUnixSeconds() {
        var value = nowUnixMs();
        return value <= 0 ? 0 : value / 1000;
    }

    public synchronized void setAuthoritativeTime(
        long serverTimeMs,
        long requestStartedTickMs,
        long responseReceivedTickMs
    ) {
        if (serverTimeMs < MIN_SERVER_TIME_MS || serverTimeMs > MAX_SERVER_TIME_MS
            || responseReceivedTickMs < requestStartedTickMs) {
            throw new SwmException.Clock("signed server time is outside the accepted range");
        }
        var roundTrip = responseReceivedTickMs - requestStartedTickMs;
        if (roundTrip > MAX_ROUND_TRIP_MS) {
            throw new SwmException.Clock("signed server time round trip is too slow");
        }
        anchorUnixMs = serverTimeMs + roundTrip / 2;
        anchorTickMs = responseReceivedTickMs;
        initialized = true;
    }

    public static long tickMs() {
        return System.nanoTime() / 1_000_000L;
    }
}
