package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// ServerSession contains the sensitive OIDC data kept on the server.
// The browser only receives the opaque ID returned by Create.
type ServerSession struct {
	State          string
	StateExpiresAt time.Time
	LogoutCSRF     string
	IDToken        string
	RefreshToken   string
	ExpiresAt      time.Time
}

func randomID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// MemoryStore stores sessions in the Gangway process. It is intentionally
// suitable for the current single-replica deployment only.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]ServerSession
	ttl      time.Duration
	maxCount int
}

// StartCleanup periodically removes expired sessions until stop is closed.
func (s *MemoryStore) StartCleanup(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.CleanupExpired()
			case <-stop:
				return
			}
		}
	}()
}

func NewMemoryStore(ttl time.Duration, maxCount ...int) *MemoryStore {
	limit := 10000
	if len(maxCount) > 0 && maxCount[0] > 0 {
		limit = maxCount[0]
	}
	return &MemoryStore{
		sessions: make(map[string]ServerSession),
		ttl:      ttl,
		maxCount: limit,
	}
}

func (s *MemoryStore) Create() (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if len(s.sessions) >= s.maxCount {
		deleteID := ""
		var oldest time.Time
		for existingID, value := range s.sessions {
			if deleteID == "" || value.ExpiresAt.Before(oldest) {
				deleteID, oldest = existingID, value.ExpiresAt
			}
		}
		if deleteID != "" {
			delete(s.sessions, deleteID)
		}
	}
	s.sessions[id] = ServerSession{ExpiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return id, nil
}

func (s *MemoryStore) Get(id string) (ServerSession, bool) {
	s.mu.RLock()
	value, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return ServerSession{}, false
	}
	now := time.Now()
	if value.State != "" && !value.StateExpiresAt.IsZero() && !value.StateExpiresAt.After(now) {
		value.State = ""
		value.StateExpiresAt = time.Time{}
	}
	if !value.ExpiresAt.After(now) {
		s.Delete(id)
		return ServerSession{}, false
	}
	return value, true
}

func (s *MemoryStore) Save(id string, value ServerSession) error {
	if id == "" {
		return errors.New("empty session ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, ok := s.sessions[id]
	if !ok {
		return errors.New("session not found")
	}
	if value.ExpiresAt.IsZero() {
		value.ExpiresAt = previous.ExpiresAt
	}
	s.sessions[id] = value
	return nil
}

func (s *MemoryStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

func (s *MemoryStore) CleanupExpired() {
	now := time.Now()
	s.mu.Lock()
	for id, value := range s.sessions {
		if !value.ExpiresAt.After(now) {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
}
