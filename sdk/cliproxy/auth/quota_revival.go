package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// quotaRevivalCheckInterval is how often the revival loop scans for eligible accounts.
	quotaRevivalCheckInterval = 60 * time.Second

	// quotaFallbackResetDuration is the fallback reset window when the API does not
	// return an explicit reset time.
	quotaFallbackResetDuration = 7 * 24 * time.Hour

	// quotaMinResetDuration is the minimum duration we treat as a weekly quota reset
	// window. Anything shorter is considered a short-term rate limit, not a quota
	// exhaustion that warrants disabling the account.
	quotaMinResetDuration = 24 * time.Hour

	whamUsageURL       = "https://chatgpt.com/backend-api/wham/usage"
	whamUsageUserAgent = "Mozilla/5.0 CLIProxyAPI/1.0"
)

// isWeeklyQuotaExhaustedError returns true when the error represents a weekly
// Codex quota exhaustion, as opposed to a short-term rate limit.
//
//   - Codex API returns: error.type == "usage_limit_reached"
//   - Standard OpenAI API returns: error.code == "insufficient_quota"
func isWeeklyQuotaExhaustedError(err *Error) bool {
	if err == nil || err.HTTPStatus != 429 {
		return false
	}
	msg := err.Message
	if strings.Contains(msg, "usage_limit_reached") {
		return true
	}
	if strings.Contains(msg, "insufficient_quota") {
		return true
	}
	return false
}

// resolveQuotaResetAt returns the best estimate for when the weekly quota resets.
//
// Priority:
//  1. retryAfter from the upstream API error (resets_at / resets_in_seconds),
//     only accepted when > quotaMinResetDuration so we don't mistake a short-term
//     rate-limit window for a weekly quota cycle.
//  2. Fallback: now + quotaFallbackResetDuration (7 days).
func resolveQuotaResetAt(retryAfter *time.Duration, now time.Time) time.Time {
	if retryAfter != nil && *retryAfter > quotaMinResetDuration {
		return now.Add(*retryAfter)
	}
	return now.Add(quotaFallbackResetDuration)
}

// fetchWhamUsageResetAt calls the wham/usage endpoint with the given access token
// and returns the primary-window reset Unix timestamp when available.
// This is called at most once per quota-exhaustion event to obtain a precise
// reset time when the upstream API error did not include one.
func fetchWhamUsageResetAt(ctx context.Context, accessToken string) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, whamUsageURL, nil)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", whamUsageUserAgent)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return time.Time{}, err
	}

	var payload struct {
		RateLimit struct {
			PrimaryWindow struct {
				ResetAt int64 `json:"reset_at"`
			} `json:"primary_window"`
		} `json:"rate_limit"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return time.Time{}, fmt.Errorf("parse wham/usage response: %w", err)
	}

	if ts := payload.RateLimit.PrimaryWindow.ResetAt; ts > 0 {
		t := time.Unix(ts, 0)
		if t.After(time.Now()) {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no future reset_at in wham/usage response")
}

// disableAuthForQuota marks the auth as disabled due to weekly quota exhaustion,
// stores the reset time in QuotaResetAt, and persists the change.
//
// initialResetAt is the best estimate computed from the upstream API error. If it
// is less than 24 h away (i.e. effectively a fallback), we make one additional
// wham/usage call to try to get a more accurate time.
//
// This function is designed to be called as a goroutine and must not block the
// hot request path.
func (m *Manager) disableAuthForQuota(authID string, initialResetAt time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	m.mu.Lock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil {
		m.mu.Unlock()
		return
	}
	if auth.Disabled {
		// Already disabled (e.g. by a concurrent call or manual action).
		m.mu.Unlock()
		return
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	m.mu.Unlock()

	resetAt := initialResetAt

	// If the initial estimate is just the fallback (exactly 7 days), try to
	// improve it with a wham/usage call while we hold no locks.
	if accessToken != "" && initialResetAt.Sub(time.Now()) >= quotaFallbackResetDuration-time.Minute {
		if t, err := fetchWhamUsageResetAt(ctx, accessToken); err == nil {
			resetAt = t
			log.WithFields(log.Fields{
				"auth_id":  authID,
				"reset_at": resetAt.Format(time.RFC3339),
			}).Debug("quota: obtained precise reset_at from wham/usage")
		}
	}

	// Re-lock and apply the state change.
	m.mu.Lock()
	auth, ok = m.auths[authID]
	if !ok || auth == nil || auth.Disabled {
		m.mu.Unlock()
		return
	}
	auth.Disabled = true
	auth.QuotaResetAt = resetAt
	auth.Status = StatusDisabled
	auth.StatusMessage = "quota exhausted"
	auth.UpdatedAt = time.Now()
	m.mu.Unlock()

	if _, err := m.Update(ctx, auth); err != nil {
		log.WithError(err).WithField("auth_id", authID).Warn("quota: failed to persist disabled state")
		return
	}

	log.WithFields(log.Fields{
		"auth_id":  authID,
		"reset_at": resetAt.Format(time.RFC3339),
	}).Info("quota: account disabled due to weekly quota exhaustion, will revive at reset_at")
}

// startQuotaRevivalLoop starts a background goroutine that periodically scans
// all disabled accounts whose QuotaResetAt has passed and re-enables them.
func (m *Manager) startQuotaRevivalLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(quotaRevivalCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.runQuotaRevivalCycle(ctx)
			}
		}
	}()
}

// runQuotaRevivalCycle finds all accounts that are disabled due to quota
// exhaustion and whose reset time has arrived, then re-enables each one.
func (m *Manager) runQuotaRevivalCycle(ctx context.Context) {
	now := time.Now()

	m.mu.RLock()
	var candidates []*Auth
	for _, auth := range m.auths {
		if auth == nil || !auth.Disabled {
			continue
		}
		if auth.QuotaResetAt.IsZero() || now.Before(auth.QuotaResetAt) {
			continue
		}
		candidates = append(candidates, auth.Clone())
	}
	m.mu.RUnlock()

	for _, auth := range candidates {
		m.reviveQuotaAuth(ctx, auth)
	}
}

// reviveQuotaAuth refreshes the OAuth token for auth and re-enables it.
func (m *Manager) reviveQuotaAuth(ctx context.Context, auth *Auth) {
	logger := log.WithField("auth_id", auth.ID)
	logger.Info("quota: reviving account")

	// Refresh the OAuth token so the account starts with a fresh token.
	refreshedAuth, err := m.refreshAuthForRevival(ctx, auth)
	if err != nil {
		logger.WithError(err).Warn("quota: token refresh failed, skipping revival")
		return
	}

	// Re-enable the account.
	refreshedAuth.Disabled = false
	refreshedAuth.QuotaResetAt = time.Time{}
	refreshedAuth.Quota = QuotaState{}
	refreshedAuth.Status = StatusActive
	refreshedAuth.StatusMessage = ""
	refreshedAuth.UpdatedAt = time.Now()

	if _, err := m.Update(ctx, refreshedAuth); err != nil {
		logger.WithError(err).Warn("quota: failed to persist revived state")
		return
	}

	logger.Info("quota: account revived successfully")
}

// refreshAuthForRevival attempts to refresh the auth token using the registered
// store. If the store is unavailable or the refresh fails it returns the original
// auth unchanged so the caller can still re-enable with the existing token.
func (m *Manager) refreshAuthForRevival(ctx context.Context, auth *Auth) (*Auth, error) {
	if m.store == nil {
		return auth, nil
	}
	refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	refreshed, err := m.store.Refresh(refreshCtx, auth)
	if err != nil {
		return nil, err
	}
	if refreshed == nil {
		return auth, nil
	}
	return refreshed, nil
}
