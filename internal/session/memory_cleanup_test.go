package session

import (
	"testing"
	"time"
)

func TestMemoryStoreCleanupExpired(t *testing.T) {
	store := NewMemoryStore(time.Millisecond)
	stop := make(chan struct{})
	store.StartCleanup(time.Millisecond, stop)
	defer close(stop)

	id, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	store.CleanupExpired()
	if _, ok := store.Get(id); ok {
		t.Fatal("cleanup did not remove expired session")
	}
}
