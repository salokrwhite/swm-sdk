package swm

import (
	"strconv"
	"strings"
	"sync"
)

const (
	offlineBudgetHeader         = "SwmSdkOfflineBudgetV1"
	maximumOfflineMilliseconds  = int64(24 * 60 * 60 * 1000)
	persistIntervalMilliseconds = int64(5 * 60 * 1000)
)

type offlineBudgetState struct {
	mu                        sync.Mutex
	store                     *stateStore
	installID                 string
	keyThumbprint             string
	loaded                    bool
	hasRecord                 bool
	latched                   bool
	hadVerifiedInteraction    bool
	lastVerifiedMilliseconds  int64
	lastPersistedMilliseconds int64
}

func newOfflineBudget(store *stateStore, installID, keyThumbprint string) *offlineBudgetState {
	return &offlineBudgetState{store: store, installID: installID, keyThumbprint: keyThumbprint}
}

func (s *offlineBudgetState) isLocked(clock *trustedClock) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLoaded()
	if s.latched {
		return true
	}
	now := clock.nowUnixMilliseconds()
	return !s.hasRecord || now <= 0 || now < s.lastVerifiedMilliseconds ||
		now-s.lastVerifiedMilliseconds > maximumOfflineMilliseconds
}

func (s *offlineBudgetState) noteVerifiedInteraction(trustedUnixMilliseconds int64) {
	if trustedUnixMilliseconds <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLoaded()
	if s.hadVerifiedInteraction && s.hasRecord &&
		trustedUnixMilliseconds >= s.lastVerifiedMilliseconds &&
		trustedUnixMilliseconds-s.lastVerifiedMilliseconds > maximumOfflineMilliseconds {
		s.latched = true
	}
	s.hadVerifiedInteraction = true
	s.hasRecord = true
	if trustedUnixMilliseconds > s.lastVerifiedMilliseconds {
		s.lastVerifiedMilliseconds = trustedUnixMilliseconds
	}
	if s.lastPersistedMilliseconds == 0 ||
		trustedUnixMilliseconds-s.lastPersistedMilliseconds >= persistIntervalMilliseconds {
		s.persist()
	}
}

func (s *offlineBudgetState) ensureLoaded() {
	if s.loaded {
		return
	}
	s.loaded = true
	plaintext, ok := s.store.readProtected(offlineFile)
	if !ok {
		return
	}
	defer zero(plaintext)
	parts := strings.Split(string(plaintext), "\n")
	if len(parts) < 4 || parts[0] != offlineBudgetHeader ||
		parts[1] != s.installID || parts[2] != s.keyThumbprint {
		return
	}
	value, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || value <= 0 {
		return
	}
	s.hasRecord = true
	s.lastVerifiedMilliseconds = value
	s.lastPersistedMilliseconds = value
}

func (s *offlineBudgetState) persist() {
	text := strings.Join([]string{
		offlineBudgetHeader,
		s.installID,
		s.keyThumbprint,
		strconv.FormatInt(s.lastVerifiedMilliseconds, 10),
	}, "\n") + "\n"
	if err := s.store.writeProtected(offlineFile, []byte(text)); err == nil {
		s.lastPersistedMilliseconds = s.lastVerifiedMilliseconds
	}
}
