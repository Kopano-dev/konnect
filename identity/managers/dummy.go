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
	"strings"

	"github.com/gorilla/mux"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

// DummyIdentityManager implements an identity manager which always grants
// access to a fixed user id.
type DummyIdentityManager struct {
	Sub string
}

type dummyUser struct {
	sub string
}

func (u *dummyUser) Subject() string {
	return u.sub
}

func (u *dummyUser) Email() string {
	return fmt.Sprintf("%s@%s.local", u.sub, u.sub)
}

func (u *dummyUser) EmailVerified() bool {
	return false
}

func (u *dummyUser) Name() string {
	return fmt.Sprintf("Foo %s", strings.Title(u.sub))
}

// Authenticate implements the identity.Manager interface.
func (im *DummyIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	return NewAuthRecord(im.Sub, nil, nil), nil
}

// Authorize implements the identity.Manager interface.
func (im *DummyIdentityManager) Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (identity.AuthRecord, error) {
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
		return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required, but page not implemented")
	}

	auth.AuthorizeScopes(approvedScopes)
	return auth, nil
}

// ApproveScopes implements the Backend interface.
func (im *DummyIdentityManager) ApproveScopes(ctx context.Context, userid string, audience string, approvedScopes map[string]bool) (string, error) {
	ref := rndm.GenerateRandomString(32)

	// TODO(longsleep): Store generated ref with provided data.
	return ref, nil
}

// ApprovedScopes implements the Backend interface.
func (im *DummyIdentityManager) ApprovedScopes(ctx context.Context, userid string, audience string, ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, fmt.Errorf("SimplePasswdBackend: invalid ref")
	}

	return nil, nil
}

// Fetch implements the identity.Manager interface.
func (im *DummyIdentityManager) Fetch(ctx context.Context, sub string, scopes map[string]bool) (identity.AuthRecord, bool, error) {
	if sub != im.Sub {
		return nil, false, fmt.Errorf("DummyIdentityManager: no user")
	}

	authorizedScopes, claims := authorizeScopes(&dummyUser{im.Sub}, scopes)
	return NewAuthRecord(sub, authorizedScopes, claims), true, nil
}

// ScopesSupported implements the identity.Manager interface.
func (im *DummyIdentityManager) ScopesSupported() []string {
	return []string{
		oidc.ScopeProfile,
		oidc.ScopeEmail,
	}
}

// ClaimsSupported implements the identity.Manager interface.
func (im *DummyIdentityManager) ClaimsSupported() []string {
	return []string{
		oidc.NameClaim,
		oidc.EmailClaim,
	}
}

// AddRoutes implements the identity.Manager interface.
func (im *DummyIdentityManager) AddRoutes(ctx context.Context, router *mux.Router) {
}
