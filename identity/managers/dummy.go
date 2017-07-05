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

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"

	"github.com/dgrijalva/jwt-go"
)

// DummyIdentityManager implements an identity manager which always grants
// access to a fixed user id.
type DummyIdentityManager struct {
	UserID string
}

type dummyUser struct {
	id string
}

func (u *dummyUser) ID() string {
	return u.id
}

func (u *dummyUser) Email() string {
	return fmt.Sprintf("%s@%s.local", u.id, u.id)
}

func (u *dummyUser) EmailVerified() bool {
	return false
}

func (u *dummyUser) Name() string {
	return fmt.Sprintf("Foo %s", strings.Title(u.id))
}

// Authenticate implements the identity.Manager interface.
func (im *DummyIdentityManager) Authenticate(rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	return NewAuthRecord(im.UserID, nil, nil), nil
}

// Authorize implements the identity.Manager interface.
func (im *DummyIdentityManager) Authorize(rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (identity.AuthRecord, error) {
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

// Fetch implements the identity.Manager interface.
func (im *DummyIdentityManager) Fetch(ctx context.Context, userID string, scopes map[string]bool) (identity.AuthRecord, bool, error) {
	if userID != im.UserID {
		return nil, false, fmt.Errorf("DummyIdentityManager: no user")
	}
	var user User
	user = &dummyUser{im.UserID}

	// TODO(longsleep): Move the code below to general function.
	authorizedScopes := make(map[string]bool)
	claims := make(map[string]jwt.Claims)
	for scope, authorizedScope := range scopes {
		if !authorizedScope {
			continue
		}
		switch scope {
		case oidc.ScopeOpenID:
			// breaks
		case oidc.ScopeEmail:
			if userWithEmail, ok := user.(UserWithEmail); ok {
				claims[oidc.ScopeEmail] = &oidc.EmailClaims{
					Email:         userWithEmail.Email(),
					EmailVerified: userWithEmail.EmailVerified(),
				}
			}
		case oidc.ScopeProfile:
			if userWithProfile, ok := user.(UserWithProfile); ok {
				claims[oidc.ScopeProfile] = &oidc.ProfileClaims{
					Name: userWithProfile.Name(),
				}
			}
		default:
			authorizedScope = false
		}
		if authorizedScope {
			authorizedScopes[scope] = true
		}
	}

	return NewAuthRecord(userID, authorizedScopes, claims), true, nil
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
