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
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/identity/clients"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

const guestIdentitityManagerName = "guest"

// GuestIdentityManager implements an identity manager for guest users.
type GuestIdentityManager struct {
	scopesSupported []string
	claimsSupported []string

	onSetLogonCallbacks   []func(ctx context.Context, rw http.ResponseWriter, user identity.User) error
	onUnsetLogonCallbacks []func(ctx context.Context, rw http.ResponseWriter) error
}

// NewGuestIdentityManager creates a new GuestIdentityManager from the
// provided parameters.
func NewGuestIdentityManager(c *identity.Config) *GuestIdentityManager {
	im := &GuestIdentityManager{
		scopesSupported: setupSupportedScopes([]string{
			konnect.ScopeGuestOK,
		}, []string{
			konnect.ScopeID,
			oidc.ScopeProfile,
			oidc.ScopeEmail,
		}, c.ScopesSupported),
		claimsSupported: []string{
			oidc.NameClaim,
			oidc.FamilyNameClaim,
			oidc.GivenNameClaim,
			oidc.EmailClaim,
			oidc.EmailVerifiedClaim,
		},

		onSetLogonCallbacks:   make([]func(ctx context.Context, rw http.ResponseWriter, user identity.User) error, 0),
		onUnsetLogonCallbacks: make([]func(ctx context.Context, rw http.ResponseWriter) error, 0),
	}

	return im
}

type guestUser struct {
	raw           string
	email         string
	emailVerified bool
	name          string
	familyName    string
	givenName     string
}

func newGuestUserFromClaims(claims jwt.MapClaims) *guestUser {
	isGuestClaim, ok := claims[konnect.IdentifiedUserIsGuest]
	if !ok {
		return nil
	}
	isGuest, _ := isGuestClaim.(bool)
	if !isGuest {
		return nil
	}

	idClaim, ok := claims[konnect.IdentifiedUserIDClaim]
	if !ok {
		return nil
	}

	dataClaim, ok := claims[konnect.IdentifiedData]
	if !ok {
		return nil
	}

	user := &guestUser{
		raw: idClaim.(string),
	}
	data, _ := dataClaim.(map[string]interface{})
	for name, value := range data {
		switch name {
		case "e":
			user.email, _ = value.(string)
		case "ev":
			if v, _ := value.(int); v == 1 {
				user.emailVerified = true
			}
		case "n":
			user.name, _ = value.(string)
		case "nf":
			user.familyName, _ = value.(string)
		case "ng":
			user.givenName, _ = value.(string)
		}
	}

	return user
}

type minimalGuestUserData struct {
	E  string `json:"e,omitempty"`
	EV int    `json:"ev,omitempty"`
	N  string `json:"n,omitempty"`
	NF string `json:"nf,omitempty"`
	NG string `json:"ng,omitempty"`
}

func (u *guestUser) Raw() string {
	return u.raw
}

func (u *guestUser) Subject() string {
	sub, _ := getPublicSubject([]byte(u.raw), []byte(guestIdentitityManagerName))
	return sub
}

func (u *guestUser) Email() string {
	return u.email
}

func (u *guestUser) EmailVerified() bool {
	return u.emailVerified
}

func (u *guestUser) Name() string {
	return u.name
}

func (u *guestUser) FamilyName() string {
	return u.familyName
}

func (u *guestUser) GivenName() string {
	return u.givenName
}

func (u *guestUser) Claims() jwt.MapClaims {
	claims := make(jwt.MapClaims)
	claims[konnect.IdentifiedUserIDClaim] = u.raw
	claims[konnect.IdentifiedUserIsGuest] = true

	m := &minimalGuestUserData{
		E:  u.email,
		N:  u.name,
		NF: u.familyName,
		NG: u.givenName,
	}
	if u.emailVerified {
		m.EV = 1
	}
	claims[konnect.IdentifiedData] = m

	return claims
}

// Authenticate implements the identity.Manager interface.
func (im *GuestIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, next identity.Manager) (identity.AuthRecord, error) {
	// Check if required scopes are there.
	if !ar.Scopes[konnect.ScopeGuestOK] {
		return nil, ar.NewError(oidc.ErrorOIDCLoginRequired, "GuestIdentityManager: required scope missing")
	}

	// Authenticate with signed client request object, so that must be there.
	if ar.Request == nil {
		return nil, ar.NewError(oidc.ErrorOIDCInvalidRequestObject, "GuestIdentityManager: no request object")
	}

	// Further checks of signed claims.
	roc, ok := ar.Request.Claims.(*payload.RequestObjectClaims)
	if !ok {
		return nil, ar.NewBadRequest(oidc.ErrorOAuth2InvalidRequest, "GuestIdentityManager: invalid claims request")
	}

	// NOTE(longsleep): Require claims in request object to ensure that the
	// claims requested come from there.
	if roc.Claims == nil || ar.Claims == nil {
		return nil, ar.NewError(oidc.ErrorOAuth2InvalidRequest, "GuestIdentityManager: missing claims request")
	}
	// NOTE(longsleep): Guest mode requires ID token claims request with the
	// guest claim set to an expected value.
	if ar.Claims.IDToken == nil {
		return nil, ar.NewError(oidc.ErrorOAuth2InvalidRequest, "GuestIdentityManager: missing claims request for id_token")
	}
	guest, ok := ar.Claims.IDToken.GetStringValue("guest")
	if !ok {
		return nil, ar.NewError(oidc.ErrorOAuth2InvalidRequest, "GuestIdentityManager: missing claim guest in id_token claims request")
	}

	// Ensure that request object claim is signed.
	if ar.Request.Method == jwt.SigningMethodNone {
		return nil, ar.NewBadRequest(oidc.ErrorOIDCInvalidRequestObject, "GuestIdentityManager: request object must be signed")
	}

	if guest == "" {
		return nil, ar.NewBadRequest(oidc.ErrorOAuth2InvalidRequest, "GuestIdentityManager: invalid claim guest in id_token claims request")
	}

	// Additional email and profile claim values will be taken over into the
	// guest user data.
	email, _ := ar.Claims.IDToken.GetStringValue(oidc.EmailClaim)
	var emailVerified bool
	if emailVerifiedRaw, ok := ar.Claims.IDToken.Get(oidc.EmailVerifiedClaim); ok {
		emailVerified, _ = emailVerifiedRaw.Value.(bool)
	}

	name, _ := ar.Claims.IDToken.GetStringValue(oidc.NameClaim)
	familyName, _ := ar.Claims.IDToken.GetStringValue(oidc.FamilyNameClaim)
	givenName, _ := ar.Claims.IDToken.GetStringValue(oidc.GivenNameClaim)

	// Make new user with the provided signed information.
	sub := guest
	user := &guestUser{
		raw:           sub,
		email:         email,
		emailVerified: emailVerified,
		name:          name,
		familyName:    familyName,
		givenName:     givenName,
	}

	// TODO(longsleep): Add additional claims to user from the claims request
	// after filtering.

	// Check request.
	err := ar.Verify(user.Subject())
	if err != nil {
		return nil, err
	}

	auth := identity.NewAuthRecord(im, user.Subject(), nil, nil, nil)
	auth.SetUser(user)

	return auth, nil
}

// Authorize implements the identity.Manager interface.
func (im *GuestIdentityManager) Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (identity.AuthRecord, error) {
	promptConsent := false
	var approvedScopes map[string]bool

	// Check prompt value.
	switch {
	case ar.Prompts[oidc.PromptConsent] == true:
		promptConsent = true
	default:
		// Let all other prompt values pass.
	}

	// TODO(longsleep): Move the code below to general function.
	// TODO(longsleep): Validate scopes and force prompt.
	approvedScopes = ar.Scopes

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

		// TODO(longsleep): Implement consent page.
		return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required, but not supported for guests")
	}

	auth.AuthorizeScopes(approvedScopes)
	return auth, nil
}

// EndSession implements the identity.Manager interface.
func (im *GuestIdentityManager) EndSession(ctx context.Context, rw http.ResponseWriter, req *http.Request, esr *payload.EndSessionRequest) error {
	// TODO(longsleep): Implement end session for guests.

	// Trigger callbacks.
	for _, f := range im.onUnsetLogonCallbacks {
		err := f(ctx, rw)
		if err != nil {
			return err
		}
	}

	return nil
}

// ApproveScopes implements the Backend interface.
func (im *GuestIdentityManager) ApproveScopes(ctx context.Context, sub string, audience string, approvedScopes map[string]bool) (string, error) {
	ref := rndm.GenerateRandomString(32)

	// TODO(longsleep): Store generated ref with provided data.
	return ref, nil
}

// ApprovedScopes implements the Backend interface.
func (im *GuestIdentityManager) ApprovedScopes(ctx context.Context, sub string, audience string, ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, fmt.Errorf("GuestIdentityManager: invalid ref")
	}

	return nil, nil
}

// Fetch implements the identity.Manager interface.
func (im *GuestIdentityManager) Fetch(ctx context.Context, userID string, sessionRef *string, scopes map[string]bool, requestedClaimsMaps []*payload.ClaimsRequestMap) (identity.AuthRecord, bool, error) {
	var user identity.PublicUser

	for {
		// First check if current context has auth.
		if auth, ok := identity.FromContext(ctx); ok {
			user = auth.User()
			break
		}
		// Second check if current context has claims with guest identity in it.
		if claims, ok := konnect.FromClaimsContext(ctx); ok {
			var identityClaims jwt.MapClaims
			var identityProvider string
			switch c := claims.(type) {
			case *konnect.AccessTokenClaims:
				identityClaims = c.IdentityClaims
				identityProvider = c.IdentityProvider
			case *konnect.RefreshTokenClaims:
				identityClaims = c.IdentityClaims
				identityProvider = c.IdentityProvider
			}
			if identityClaims != nil && identityProvider == im.Name() {
				user = newGuestUserFromClaims(identityClaims)
				break
			}
		}

		return nil, false, fmt.Errorf("GuestIdentityManager: no user in context")
	}

	if user.Raw() != userID {
		return nil, false, fmt.Errorf("GuestIdentityManager: wrong user")
	}

	authorizedScopes, _ := identity.AuthorizeScopes(im, user, scopes)
	claims := identity.GetUserClaimsForScopes(user, authorizedScopes, requestedClaimsMaps)

	auth := identity.NewAuthRecord(im, user.Subject(), authorizedScopes, nil, claims)
	auth.SetUser(user)

	return auth, true, nil
}

// Name implements the identity.Manager interface.
func (im *GuestIdentityManager) Name() string {
	return guestIdentitityManagerName
}

// ScopesSupported implements the identity.Manager interface.
func (im *GuestIdentityManager) ScopesSupported() []string {
	return im.scopesSupported
}

// ClaimsSupported implements the identity.Manager interface.
func (im *GuestIdentityManager) ClaimsSupported() []string {
	return im.claimsSupported
}

// AddRoutes implements the identity.Manager interface.
func (im *GuestIdentityManager) AddRoutes(ctx context.Context, router *mux.Router) {
}

// OnSetLogon implements the identity.Manager interface.
func (im *GuestIdentityManager) OnSetLogon(cb func(ctx context.Context, rw http.ResponseWriter, user identity.User) error) error {
	im.onSetLogonCallbacks = append(im.onSetLogonCallbacks, cb)
	return nil
}

// OnUnsetLogon implements the identity.Manager interface.
func (im *GuestIdentityManager) OnUnsetLogon(cb func(ctx context.Context, rw http.ResponseWriter) error) error {
	im.onUnsetLogonCallbacks = append(im.onUnsetLogonCallbacks, cb)
	return nil
}

// GetClientRegistration implements the identity.Manager interface.
func (im *GuestIdentityManager) GetClientRegistration(ctx context.Context, clientID string) (*clients.ClientRegistration, bool) {
	return nil, false
}
