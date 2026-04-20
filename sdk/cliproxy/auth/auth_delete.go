package auth

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// isTokenExpiredError returns true when a 401 response indicates the access
// token has expired but the account itself is still valid. In this case the
// refresh token should still work and we can recover by re-running the OAuth
// refresh flow.
func isTokenExpiredError(err *Error) bool {
	if err == nil || err.HTTPStatus != 401 {
		return false
	}
	msg := strings.ToLower(err.Message)
	for _, signal := range []string{
		"token_expired",
		"token expired",
		"access token expired",
		"authentication token is expired",
		"token_invalidated",
		"token has been invalidated",
		"authentication token has been invalidated",
	} {
		if strings.Contains(msg, signal) {
			return true
		}
	}
	return false
}

// isIrrecoverableAuthError returns true when a 401 response signals a permanent
// credential failure that cannot be fixed by retrying or token refresh.
//
// Detected signals (subset of cleaner's P401/PREMOVE patterns):
//   - invalid_grant        : OAuth refresh token revoked
//   - refresh_token_reused : refresh token reuse detected (security block)
//   - account_deactivated  : account banned / closed by provider
//   - account_disabled     : account disabled by provider
//
// Deliberately conservative: generic "unauthorized" or "token_expired" are NOT
// included because the auto-refresh loop can recover those.
func isIrrecoverableAuthError(err *Error) bool {
	if err == nil || err.HTTPStatus != 401 {
		return false
	}
	msg := strings.ToLower(err.Message)
	for _, signal := range []string{
		"invalid_grant",
		"refresh_token_reused",
		"account_deactivated",
		"account deactivated",
		"account has been deactivated",
		"account_disabled",
		"account disabled",
		"account has been disabled",
	} {
		if strings.Contains(msg, signal) {
			return true
		}
	}
	return false
}

// deleteAuthPermanent removes an auth entry whose credentials are permanently
// invalid or have been consumed (e.g. refresh token revoked, account banned,
// token_expired with no recoverable refresh token). It:
//  1. Deletes the backing file via the store (FileTokenStore.Delete calls os.Remove).
//  2. Purges the entry from the in-memory auth map.
//  3. Evicts it from the scheduler and the refresh loop.
//
// Designed to be launched as a goroutine so it never blocks the request path.
func (m *Manager) deleteAuthPermanent(authID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	m.mu.RLock()
	auth, ok := m.auths[authID]
	if !ok || auth == nil {
		m.mu.RUnlock()
		return
	}
	var filePath string
	if auth.Attributes != nil {
		filePath = strings.TrimSpace(auth.Attributes["path"])
	}
	m.mu.RUnlock()

	// Delete the backing file. FileTokenStore.Delete calls os.Remove internally.
	if m.store != nil && filePath != "" {
		if err := m.store.Delete(ctx, filePath); err != nil {
			log.WithError(err).WithField("auth_id", authID).Warn("auth-delete: failed to delete auth file, purging in-memory state anyway")
		}
	}

	// Purge from in-memory map.
	m.mu.Lock()
	delete(m.auths, authID)
	m.mu.Unlock()

	// Evict from scheduler so it is no longer considered for routing.
	if m.scheduler != nil {
		m.scheduler.removeAuth(authID)
	}

	// Evict from refresh loop.
	if m.refreshLoop != nil {
		m.refreshLoop.remove(authID)
	}

	log.WithField("auth_id", authID).Info("auth-delete: account permanently deleted (token_expired / invalid_grant / account deactivated)")
}
