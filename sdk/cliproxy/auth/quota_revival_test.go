package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

type deletingStore struct {
	deleted chan string
}

func (s *deletingStore) List(context.Context) ([]*Auth, error) { return nil, nil }

func (s *deletingStore) Save(context.Context, *Auth) (string, error) { return "", nil }

func (s *deletingStore) Delete(_ context.Context, id string) error {
	select {
	case s.deleted <- id:
	default:
	}
	return nil
}

func TestIsWhamUsageTokenExpiredError(t *testing.T) {
	err := &whamUsageError{
		statusCode: 401,
		body:       `{"error":{"message":"Provided authentication token is expired. Please try signing in again."}}`,
	}
	if !isWhamUsageTokenExpiredError(err) {
		t.Fatalf("expected expired wham/usage 401 to be recognized")
	}
}

func TestDisableAuthForQuota_DeletesAuthOnExpiredWhamUsage401(t *testing.T) {
	store := &deletingStore{deleted: make(chan string, 1)}
	mgr := NewManager(store, nil, nil)
	authID := "auth-wham-expired"
	authPath := "/tmp/auth-wham-expired.json"

	if _, err := mgr.Register(context.Background(), &Auth{
		ID:       authID,
		Provider: "codex",
		Status:   StatusActive,
		Metadata: map[string]any{
			"access_token": "test-access-token",
		},
		Attributes: map[string]string{
			"path": authPath,
		},
	}); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	initialResetAt := time.Now().Add(quotaFallbackResetDuration)
	mgr.disableAuthForQuotaWithUsageProbe(
		authID,
		initialResetAt,
		func(context.Context, string) (time.Time, error) {
			return time.Time{}, &whamUsageError{
				statusCode: 401,
				body:       `{"error":{"message":"Provided authentication token is expired. Please try signing in again."}}`,
			}
		},
	)

	select {
	case deletedPath := <-store.deleted:
		if deletedPath != authPath {
			t.Fatalf("Delete() path = %q, want %q", deletedPath, authPath)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for auth deletion")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := mgr.GetByID(authID); !ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected auth to be removed from manager after expired wham/usage 401")
}

func TestIsWhamUsageTokenExpiredError_RejectsNonExpired401(t *testing.T) {
	err := &whamUsageError{
		statusCode: 401,
		body:       `{"error":{"message":"Unauthorized"}}`,
	}
	if isWhamUsageTokenExpiredError(err) {
		t.Fatalf("unexpected token-expired match for generic 401")
	}
}

func TestIsWhamUsageTokenExpiredError_RejectsWrappedNonWhamError(t *testing.T) {
	err := errors.New("401 Provided authentication token is expired")
	if isWhamUsageTokenExpiredError(err) {
		t.Fatalf("expected only whamUsageError to match")
	}
}
