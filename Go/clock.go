package swm

import (
	"sync"
	"time"
)

const (
	maximumClockRoundTrip = 5 * time.Second
	minimumServerTimeMS   = int64(1577836800000)
	maximumServerTimeMS   = int64(4102444800000)
)

type trustedClock struct {
	mu               sync.Mutex
	initialized      bool
	anchorUnixMillis int64
	anchorMonotonic  time.Time
}

func (c *trustedClock) setAuthoritativeTime(serverTimeMS int64, started, received time.Time) error {
	if serverTimeMS < minimumServerTimeMS || serverTimeMS > maximumServerTimeMS ||
		received.Before(started) {
		return newError(KindClock, "server time", "clock_invalid", "signed server time is outside the accepted range")
	}
	roundTrip := received.Sub(started)
	if roundTrip > maximumClockRoundTrip {
		return newError(KindClock, "server time", "clock_round_trip", "signed server time round trip is too slow")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anchorUnixMillis = serverTimeMS + roundTrip.Milliseconds()/2
	c.anchorMonotonic = received
	c.initialized = true
	return nil
}

func (c *trustedClock) nowUnixMilliseconds() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.initialized {
		return 0
	}
	elapsed := time.Since(c.anchorMonotonic)
	if elapsed < 0 {
		return 0
	}
	return c.anchorUnixMillis + elapsed.Milliseconds()
}

func (c *trustedClock) nowUnixSeconds() int64 {
	millis := c.nowUnixMilliseconds()
	if millis <= 0 {
		return 0
	}
	return millis / 1000
}

func (c *trustedClock) isInitialized() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.initialized
}

func timeNowUnixMilliseconds() int64 {
	return time.Now().UnixMilli()
}
