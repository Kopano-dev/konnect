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

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/version"
)

// CookieIdentityManager implements an identity manager which passes through
// received HTTP cookies to a HTTP backend..
type CookieIdentityManager struct {
	*EncryptionManager

	backendURI     *url.URL
	allowedCookies map[string]bool

	signInFormURI string
	logger        logrus.FieldLogger

	client *http.Client
}

// NewCookieIdentityManager creates a new CookieIdentityManager from the
// provided parameters.
func NewCookieIdentityManager(c *identity.Config, em *EncryptionManager, backendURI *url.URL, cookieNames []string, timeout time.Duration, transport http.RoundTripper) *CookieIdentityManager {
	if transport == nil {
		transport = http.DefaultTransport
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	var allowedCookies map[string]bool
	if len(cookieNames) != 0 {
		allowedCookies = make(map[string]bool)
		for _, n := range cookieNames {
			allowedCookies[n] = true
		}
	}

	im := &CookieIdentityManager{
		EncryptionManager: em,

		backendURI:     backendURI,
		allowedCookies: allowedCookies,

		signInFormURI: c.SignInFormURI.String(),
		logger:        c.Logger,

		client: client,
	}

	return im
}

type cookieUser struct {
	sub   string
	name  string
	email string

	id     int64
	claims jwt.MapClaims
}

func (u *cookieUser) Subject() string {
	return u.sub
}

func (u *cookieUser) Name() string {
	return u.name
}

func (u *cookieUser) Email() string {
	return u.email
}

func (u *cookieUser) EmailVerified() bool {
	return false
}

func (u *cookieUser) ID() int64 {
	return u.id
}

func (u *cookieUser) Claims() jwt.MapClaims {
	return u.claims
}

type cookieBackendResponse struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`

	ID int64 `json:"id"`
}

func (im *CookieIdentityManager) backendRequest(ctx context.Context, encodedCookies string, headers http.Header) (*cookieUser, error) {
	if encodedCookies == "" {
		// Fastpath, do nothing when no cookies.
		return nil, nil
	}

	request, err := http.NewRequest(http.MethodPost, im.backendURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Copy over some request headers which are used for fingerprinting sessions.
	request.Header.Set("Accept-Language", headers.Get("Accept-Language"))
	request.Header.Set("User-Agent", headers.Get("User-Agent"))

	request.Header.Set("Connection", "keep-alive") // XXX(longsleep): This is part of the Kopano Webapp finger print and we do not really know what the browser sent on sign-in :/
	request.Header.Set("X-Konnect-Request", fmt.Sprintf("1/%s", version.Version))

	request.Header.Set("Cookie", encodedCookies)
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
		return nil, fmt.Errorf("request returned error code: %v", response.StatusCode)
	}

	payload := &cookieBackendResponse{}
	err = json.Unmarshal(body, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	encryptedCookies, err := im.EncryptStringToHexString(encodedCookies)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt cookies: %v", err)
	}

	claims := make(jwt.MapClaims)
	claims["cookie.v"] = encryptedCookies
	claims["cookie.al"] = headers.Get("Accept-Language")
	claims["cookie.ua"] = headers.Get("User-Agent")

	user := &cookieUser{
		sub:   payload.Subject,
		email: payload.Email,
		name:  payload.Name,

		id:     payload.ID,
		claims: claims,
	}

	return user, nil
}

// Authenticate implements the identity.Manager interface.
func (im *CookieIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	// Process incoming cookies, filter, and encode to string.
	var encodedCookies []string
	for _, cookie := range req.Cookies() {
		if im.allowedCookies != nil {
			if allowed, _ := im.allowedCookies[cookie.Name]; !allowed {
				continue
			}
		}

		encodedCookies = append(encodedCookies, cookie.String())
	}
	encodedCookiesString := strings.Join(encodedCookies, "; ")

	user, err := im.backendRequest(ctx, encodedCookiesString, req.Header)
	if err != nil {
		// Error, directly return.
		im.logger.Errorln("CookieIdentityManager: backend request error", err)
		return nil, ar.NewError(oidc.ErrorOAuth2ServerError, "CookieIdentityManager: backend request error")
	}
	if user == nil {
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
		u, _ := url.Parse(im.signInFormURI)
		return nil, identity.NewLoginRequiredError(err.Error(), u)
	}

	auth := NewAuthRecord(user.Subject(), nil, nil)
	auth.SetUser(user)

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
			im.logger.Debugln("consent is required for offline access but not given, removed offline_access scope")
		} else {
			// NOTE(longsleep): Cookie identity relies on the presence of session cookies know to a backend. Thus offline access is not supported.
			im.logger.Warnf("CookieIdentityManager: offline_access requested but not supported, removed offline_access scope")
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

// ApproveScopes implements the Backend interface.
func (im *CookieIdentityManager) ApproveScopes(ctx context.Context, userid string, audience string, approvedScopes map[string]bool) (string, error) {
	ref := rndm.GenerateRandomString(32)

	// TODO(longsleep): Store generated ref with provided data.
	return ref, nil
}

// ApprovedScopes implements the Backend interface.
func (im *CookieIdentityManager) ApprovedScopes(ctx context.Context, userid string, audience string, ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, fmt.Errorf("SimplePasswdBackend: invalid ref")
	}

	return nil, nil
}

// Fetch implements the identity.Manager interface.
func (im *CookieIdentityManager) Fetch(ctx context.Context, sub string, scopes map[string]bool) (identity.AuthRecord, bool, error) {
	var user identity.User

	// Try identty from context.
	auth, _ := identity.FromContext(ctx)
	if auth != nil {
		if auth.Subject() != sub {
			return nil, false, fmt.Errorf("CookieIdentityManager: wrong user - this should not happen")
		}

		user = auth.User() // This gets the user when added during Authenticate.
	}

	if user == nil {
		// Try claims from context.
		identityClaims, _ := konnect.FromClaimsContext(ctx)
		if identityClaims != nil {
			var err error
			var encodedCookies string
			identityClaimsMap, ok := identityClaims.(jwt.MapClaims)
			if !ok {
				return nil, false, fmt.Errorf("CookieIdentityManager: unknown identity claims type")
			}
			encryptedCookies, _ := identityClaimsMap["cookie.v"].(string)
			if encryptedCookies != "" {
				encodedCookies, err = im.DecryptHexToString(encryptedCookies)
				if err != nil {
					return nil, false, fmt.Errorf("CookieIdentityManager: %v", err)
				}
			} else {
				encodedCookies = encryptedCookies
			}

			headers := http.Header{}
			if al, ok := identityClaimsMap["cookie.al"]; ok {
				headers.Set("Accept-Language", al.(string))
			}
			if ua, ok := identityClaimsMap["cookie.ua"]; ok {
				headers.Set("User-Agent", ua.(string))
			}
			user, err = im.backendRequest(ctx, encodedCookies, headers)
			if err != nil {
				// Error, directly return.
				im.logger.WithError(err).Errorln("CookieIdentityManager: backend request error")
				return nil, false, fmt.Errorf("CookieIdentityManager: backend request error")
			}
		}
	}

	if user == nil {
		return nil, false, fmt.Errorf("CookieIdentityManager: no user")
	}

	if user.Subject() != sub {
		return nil, false, fmt.Errorf("CookieIdentityManager: wrong user")
	}

	authorizedScopes, claims := authorizeScopes(user, scopes)

	auth = NewAuthRecord(sub, authorizedScopes, claims)
	auth.SetUser(user)

	return auth, true, nil
}

// ScopesSupported implements the identity.Manager interface.
func (im *CookieIdentityManager) ScopesSupported() []string {
	return []string{
		oidc.ScopeProfile,
		oidc.ScopeEmail,
		konnect.ScopeID,
	}
}

// ClaimsSupported implements the identity.Manager interface.
func (im *CookieIdentityManager) ClaimsSupported() []string {
	return []string{
		oidc.NameClaim,
		oidc.EmailClaim,
	}
}

// AddRoutes implements the identity.Manager interface.
func (im *CookieIdentityManager) AddRoutes(ctx context.Context, router *mux.Router) {
}
