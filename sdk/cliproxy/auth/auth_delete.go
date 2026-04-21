package auth

import (
	"context"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// isTokenExpiredError returns true for any 401 response.
//
// When a 401 reaches the request handler, the proactive auto-refresh loop has
// already had the opportunity to recover a simple token expiry. Any 401 that
// still surfaces here means the credentials are broken beyond what a token
// refresh can fix. Deleting the auth file lets the bihourly rebind task
// restore the account via a fresh OAuth flow.
func isTokenExpiredError(err *Error) bool {
	return err != nil && err.HTTPStatus == 401
}

// isIrrecoverableAuthError is kept for semantic clarity but is now superseded
// by isTokenExpiredError covering all 401s. It remains to handle cases where
// the account should also be marked deactivated in the DB (account_deactivated /
// account_disabled signals).
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
