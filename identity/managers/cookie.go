/*
 * Copyright 2017 Kopano and its licensors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package managers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/version"
)

// CookieIdentityManager implements an identity manager which passes through
// received HTTP cookies to a HTTP backend..
type CookieIdentityManager struct {
	url    *url.URL
	client *http.Client
}

// NewCookieIdentityManager creates a new CookieIdentityManager from the
// provided parameters.
func NewCookieIdentityManager(url *url.URL, timeout time.Duration, transport http.RoundTripper) *CookieIdentityManager {
	if transport == nil {
		transport = http.DefaultTransport
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	im := &CookieIdentityManager{
		url:    url,
		client: client,
	}

	return im
}

type cookieUser struct {
	id    string
	nid   int64
	email string
	name  string
}

func (u *cookieUser) ID() string {
	return u.id
}

func (u *cookieUser) Email() string {
	return u.email
}

func (u *cookieUser) EmailVerified() bool {
	return false
}

func (u *cookieUser) Name() string {
	return u.name
}

func (u *cookieUser) NumericID() int64 {
	return u.nid
}

type cookieBackendResponse struct {
	ID        string `json:"id"`
	NumericID int64  `json:"nid"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}

// Authenticate implements the identity.Manager interface.
func (im *CookieIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	request, err := http.NewRequest(http.MethodGet, im.url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("CookieIdentityManager failed to create request: %v", err)
	}
	request.Header.Set("User-Agent", fmt.Sprintf("konnect/%s", version.Version))
	request.Header.Set("X-Konnect-Request", "1")

	request = request.WithContext(ctx)
	response, err := im.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("CookieIdentityManager request failed: %v", err)
	}
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("CookieIdentityManager read response failed: %v", err)
	}

	switch response.StatusCode {
	case http.StatusOK:
		fallthrough
	case http.StatusAccepted:
		// breaks
	default:
		return nil, fmt.Errorf("CookieIdentityManager request returned error code: %v", response.Status)
	}

	payload := &cookieBackendResponse{}
	err = json.Unmarshal(body, payload)
	if err != nil {
		return nil, fmt.Errorf("CookieIdentityManager failed to parse response: %v", err)
	}

	auth := NewAuthRecord(payload.ID, nil, nil)
	auth.SetUser(&cookieUser{
		id:    auth.UserID(),
		nid:   payload.NumericID,
		email: payload.Email,
		name:  payload.Name,
	})

	return auth, nil
}

// Authorize implements the identity.Manager interface.
func (im *CookieIdentityManager) Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (identity.AuthRecord, error) {
	// TODO(longsleep): Implement proper consent and scope checks.
	auth.AuthorizeScopes(ar.Scopes)
	return auth, nil
}

// Fetch implements the identity.Manager interface.
func (im *CookieIdentityManager) Fetch(ctx context.Context, userID string, scopes map[string]bool) (identity.AuthRecord, bool, error) {
	auth, ok := identity.FromContext(ctx)
	if !ok {
		return nil, false, fmt.Errorf("CookieIdentityManager: no auth, cookie identities only support single request fetch")
	}

	if auth.UserID() != userID {
		return nil, false, fmt.Errorf("CookieIdentityManager: wrong user - this should not happen")
	}

	user := auth.User() // This gets the user when added during Authenticate.
	if user == nil {
		return nil, false, fmt.Errorf("CookieIdentityManager: no user")
	}

	authorizedScopes, claims := authorizeScopes(user, scopes)
	return NewAuthRecord(userID, authorizedScopes, claims), true, nil
}

// ScopesSupported implements the identity.Manager interface.
func (im *CookieIdentityManager) ScopesSupported() []string {
	return []string{
		oidc.ScopeProfile,
		oidc.ScopeEmail,
	}
}

// ClaimsSupported implements the identity.Manager interface.
func (im *CookieIdentityManager) ClaimsSupported() []string {
	return []string{
		oidc.NameClaim,
		oidc.EmailClaim,
	}
}
