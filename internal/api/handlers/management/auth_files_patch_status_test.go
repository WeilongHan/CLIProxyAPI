package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

func TestPatchAuthFileStatus_EnableClearsQuotaResetMarker(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	record := &coreauth.Auth{
		ID:           "test.json",
		FileName:     "test.json",
		Provider:     "codex",
		Disabled:     true,
		Status:       coreauth.StatusDisabled,
		QuotaResetAt: time.Now().Add(time.Hour),
		Attributes: map[string]string{
			"path": "/tmp/test.json",
		},
		Metadata: map[string]any{
			"type":           "codex",
			"quota_reset_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

	body := `{"name":"test.json","disabled":false}`
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/status", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req
	h.PatchAuthFileStatus(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	updated, ok := manager.GetByID("test.json")
	if !ok || updated == nil {
		t.Fatalf("expected auth record to exist after patch")
	}
	if updated.Disabled {
		t.Fatalf("expected auth to be enabled")
	}
	if !updated.QuotaResetAt.IsZero() {
		t.Fatalf("expected QuotaResetAt to be cleared, got %v", updated.QuotaResetAt)
	}
	if _, ok := updated.Metadata["quota_reset_at"]; ok {
		t.Fatalf("expected metadata quota_reset_at to be deleted")
	}
}
