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
	"strings"
	"time"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/version"

	"github.com/sirupsen/logrus"
)

// CookieIdentityManager implements an identity manager which passes through
// received HTTP cookies to a HTTP backend..
type CookieIdentityManager struct {
	backendURI *url.URL
	client     *http.Client

	signInFormURI string

	logger logrus.FieldLogger
}

// NewCookieIdentityManager creates a new CookieIdentityManager from the
// provided parameters.
func NewCookieIdentityManager(c *identity.Config, backendURI *url.URL, timeout time.Duration, transport http.RoundTripper) *CookieIdentityManager {
	if transport == nil {
		transport = http.DefaultTransport
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	im := &CookieIdentityManager{
		backendURI: backendURI,
		client:     client,

		signInFormURI: c.SignInFormURI.String(),

		logger: c.Logger,
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

func (im *CookieIdentityManager) backendRequest(ctx context.Context, cookies []*http.Cookie) (*cookieBackendResponse, error) {
	if len(cookies) == 0 {
		// Fastpath, do nothing when no cookies.
		return nil, nil
	}

	request, err := http.NewRequest(http.MethodPost, im.backendURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	request.Header.Set("User-Agent", fmt.Sprintf("konnect/%s", version.Version))
	request.Header.Set("X-Konnect-Request", "1")

	var encodedCookies []string
	for _, cookie := range cookies {
		encodedCookies = append(encodedCookies, cookie.String())
	}
	request.Header.Set("Cookie", strings.Join(encodedCookies, "; "))
	request = request.WithContext(ctx)

	response, err := im.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	body, err := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read response failed: %v", err)
	}

	switch response.StatusCode {
	case http.StatusOK:
		fallthrough
	case http.StatusAccepted:
		// breaks
	case http.StatusUnauthorized:
		fallthrough
	case http.StatusForbidden:
		// Not signed in.
		return nil, nil
	default:
		return nil, fmt.Errorf("request returned error code: %v", response.Status)
	}

	payload := &cookieBackendResponse{}
	err = json.Unmarshal(body, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return payload, nil
}

// Authenticate implements the identity.Manager interface.
func (im *CookieIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	payload, err := im.backendRequest(ctx, req.Cookies())
	if err != nil {
		// Error, directly return.
		im.logger.Errorln("CookieIdentityManager: backend request error", err)
		return nil, ar.NewError(oidc.ErrorOAuth2ServerError, "CookieIdentityManager: backend request error")
	}
	if payload == nil {
		// Not signed in.
		err = ar.NewError(oidc.ErrorOIDCLoginRequired, "CookieIdentityManager: not signed in")
	}

	// Check prompt value.
	switch {
	case ar.Prompts[oidc.PromptNone] == true:
		if err != nil {
			// Never show sign-in, directly return error.
			return nil, err
		}
	case ar.Prompts[oidc.PromptLogin] == true:
		if err == nil {
			// Enforce to show sign-in, when signed in.
			err = ar.NewError(oidc.ErrorOIDCLoginRequired, "CookieIdentityManager: prompt=login request")
		}
	case ar.Prompts[oidc.PromptSelectAccount] == true:
		// Not supported, just ignore.
		fallthrough
	default:
		// Let all other prompt values pass.
	}

	if err != nil {
		redirectURI, _ := url.Parse(im.signInFormURI)
		redirectURI.RawQuery = fmt.Sprintf("continue=%s&oauth=1", url.QueryEscape(req.RequestURI))
		return nil, identity.NewRedirectError(err.Error(), redirectURI)
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
	promptConsent := false
	var approvedScopes map[string]bool

	// Check prompt value.
	switch {
	case ar.Prompts[oidc.PromptConsent] == true:
		promptConsent = true
	default:
		// Let all other prompt values pass.
	}

	// Fastpath for known clients.
	switch ar.ClientID {
	default:
		// TODO(longsleep): Implement previous consent checks via backend.
		approvedScopes = ar.Scopes
	}

	// Offline access validation.
	// http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	if ok, _ := ar.Scopes[oidc.ScopeOfflineAccess]; ok {
		if !promptConsent {
			// Ensure that the prompt parameter contains consent unless
			// other conditions for processing the request permitting offline
			// access to the requested resources are in place; unless one or
			// both of these conditions are fulfilled, then it MUST ignore the
			// offline_access request,
			delete(ar.Scopes, oidc.ScopeOfflineAccess)
		}
	}

	if promptConsent {
		if ar.Prompts[oidc.PromptNone] == true {
			return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required")
		}

		// TODO(longsleep): Implement permissions page / consent prompt.
		return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required")
	}

	auth.AuthorizeScopes(approvedScopes)
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
