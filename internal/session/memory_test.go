package session

import (
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	store := NewMemoryStore(time.Hour)
	id, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	want := ServerSession{State: "state", IDToken: "id", RefreshToken: "refresh"}
	if err := store.Save(id, want); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get(id)
	if !ok || got.State != want.State || got.IDToken != want.IDToken || got.RefreshToken != want.RefreshToken {
		t.Fatalf("unexpected session: %#v, %v", got, ok)
	}
}

func TestMemoryStoreExpires(t *testing.T) {
	store := NewMemoryStore(time.Millisecond)
	id, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, ok := store.Get(id); ok {
		t.Fatal("expired session was returned")
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	store := NewMemoryStore(time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := store.Create()
			if err != nil {
				t.Error(err)
				return
			}
			if err := store.Save(id, ServerSession{IDToken: "id"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestMemoryStoreMaxCountEvictsOldest(t *testing.T) {
	store := NewMemoryStore(time.Hour, 2)
	first, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	second, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(first); ok {
		t.Fatal("oldest session was not evicted")
	}
	if _, ok := store.Get(second); !ok {
		t.Fatal("second session was unexpectedly evicted")
	}
	if _, ok := store.Get(third); !ok {
		t.Fatal("new session was not retained")
	}
}

func TestMemoryStoreStateExpires(t *testing.T) {
	store := NewMemoryStore(time.Hour)
	id, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id, ServerSession{State: "state", StateExpiresAt: time.Now().Add(time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	value, ok := store.Get(id)
	if !ok {
		t.Fatal("session expired together with OAuth state")
	}
	if value.State != "" || !value.StateExpiresAt.IsZero() {
		t.Fatalf("expired OAuth state was retained: %#v", value)
	}
}

func TestMemoryStoreSaveDoesNotExtendSessionTTL(t *testing.T) {
	store := NewMemoryStore(20 * time.Millisecond)
	id, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	initial, ok := store.Get(id)
	if !ok {
		t.Fatal("created session was not found")
	}
	time.Sleep(5 * time.Millisecond)
	if err := store.Save(id, ServerSession{IDToken: "id"}); err != nil {
		t.Fatal(err)
	}
	saved, ok := store.Get(id)
	if !ok {
		t.Fatal("saved session was not found")
	}
	if !saved.ExpiresAt.Equal(initial.ExpiresAt) {
		t.Fatalf("Save changed absolute expiry: before %s, after %s", initial.ExpiresAt, saved.ExpiresAt)
	}
}
