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
	"net/url"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identifier"
	"stash.kopano.io/kc/konnect/identifier/clients"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/utils"
)

// IdentifierIdentityManager implements an identity manager which relies on
// Konnect its identifier to provide identity.
type IdentifierIdentityManager struct {
	signInFormURI string

	identifier *identifier.Identifier
	clients    *clients.Registry
	logger     logrus.FieldLogger
}

// NewIdentifierIdentityManager creates a new IdentifierIdentityManager from the provided
// parameters.
func NewIdentifierIdentityManager(c *identity.Config, i *identifier.Identifier, clients *clients.Registry) *IdentifierIdentityManager {
	im := &IdentifierIdentityManager{
		signInFormURI: c.SignInFormURI.String(),

		identifier: i,
		clients:    clients,
		logger:     c.Logger,
	}

	return im
}

// Authenticate implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (identity.AuthRecord, error) {
	var user *identifier.IdentifiedUser
	var err error

	identifiedUser, _ := im.identifier.GetUserFromLogonCookie(ctx, req, ar.MaxAge)
	if identifiedUser != nil {
		// TODO(longsleep): Add other user meta data.
		user = identifiedUser
	} else {
		// Not signed in.
		err = ar.NewError(oidc.ErrorOIDCLoginRequired, "IdentifierIdentityManager: not signed in")
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
			err = ar.NewError(oidc.ErrorOIDCLoginRequired, "IdentifierIdentityManager: prompt=login request")
		}
	case ar.Prompts[oidc.PromptSelectAccount] == true:
		if err == nil {
			// Enforce to show sign-in, when signed in.
			err = ar.NewError(oidc.ErrorOIDCLoginRequired, "IdentifierIdentityManager: prompt=select_account request")
		}
	default:
		// Let all other prompt values pass.
	}

	if err != nil {
		u, _ := url.Parse(im.signInFormURI)
		u.RawQuery = fmt.Sprintf("flow=%s&%s", identifier.FlowOIDC, req.URL.RawQuery)
		utils.WriteRedirect(rw, http.StatusFound, u, nil, false)

		return nil, &identity.IsHandledError{}
	}

	auth := NewAuthRecord(user.Subject(), nil, nil)
	auth.SetUser(user)
	if loggedOn, logonAt := identifiedUser.LoggedOn(); loggedOn {
		auth.SetAuthTime(logonAt)
	}

	return auth, nil
}

// Authorize implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (identity.AuthRecord, error) {
	promptConsent := false
	var approvedScopes map[string]bool

	// Check prompt value.
	switch {
	case ar.Prompts[oidc.PromptConsent] == true:
		promptConsent = true
	default:
		// Let all other prompt values pass.
	}

	clientDetails, err := im.clients.Lookup(req.Context(), ar.ClientID, ar.RedirectURI)
	if err != nil {
		return nil, err
	}

	// If not trusted, always force consent.
	if clientDetails.Trusted {
		approvedScopes = ar.Scopes
	} else {
		promptConsent = true
	}

	// Check given consent.
	consent, err := im.identifier.GetConsentFromConsentCookie(req.Context(), rw, req)
	if err != nil {
		return nil, err
	}
	if consent != nil {
		if !consent.Allow {
			return auth, ar.NewError(oidc.ErrorOAuth2AccessDenied, "consent denied")
		}

		promptConsent = false
		approvedScopes = consent.ApprovedScopes(ar.Scopes)
	}

	if promptConsent {
		if ar.Prompts[oidc.PromptNone] == true {
			return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required")
		}

		u, _ := url.Parse(im.signInFormURI)
		u.RawQuery = fmt.Sprintf("flow=%s&%s", identifier.FlowConsent, req.URL.RawQuery)
		utils.WriteRedirect(rw, http.StatusFound, u, nil, false)

		return nil, &identity.IsHandledError{}
	}

	// Offline access validation.
	// http://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess
	if ok, _ := approvedScopes[oidc.ScopeOfflineAccess]; ok {
		var ignoreOfflineAccessErr error
		for {
			if ok, _ := ar.ResponseTypes[oidc.ResponseTypeCode]; !ok {
				// MUST ignore the offline_access request unless the Client is using
				// a response_type value that would result in an Authorization
				// Code being returned,
				ignoreOfflineAccessErr = fmt.Errorf("response_type=code required, %#v", ar.ResponseTypes)
				break
			}

			if clientDetails.Trusted {
				// Always allow offline access for trusted clients. This qualifies
				// for other conditions.
				break
			}

			if ok, _ := ar.Prompts[oidc.PromptConsent]; !ok && consent == nil {
				// Ensure that the prompt parameter contains consent unless
				// other conditions for processing the request permitting offline
				// access to the requested resources are in place; unless one or
				// both of these conditions are fulfilled, then it MUST ignore the
				// offline_access request,
				ignoreOfflineAccessErr = fmt.Errorf("prompt=consent required, %#v", ar.Prompts)
				break
			}

			break
		}

		if ignoreOfflineAccessErr != nil {
			delete(approvedScopes, oidc.ScopeOfflineAccess)
			im.logger.WithError(ignoreOfflineAccessErr).Debugln("removed offline_access scope")
		}
	}

	auth.AuthorizeScopes(approvedScopes)
	return auth, nil
}

// ApproveScopes implements the Backend interface.
func (im *IdentifierIdentityManager) ApproveScopes(ctx context.Context, userid string, audience string, approvedScopes map[string]bool) (string, error) {
	ref := rndm.GenerateRandomString(32)

	// TODO(longsleep): Store generated ref with provided data.
	return ref, nil
}

// ApprovedScopes implements the Backend interface.
func (im *IdentifierIdentityManager) ApprovedScopes(ctx context.Context, userid string, audience string, ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, fmt.Errorf("IdentifierIdentityManager: invalid ref")
	}

	return nil, nil
}

// Fetch implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Fetch(ctx context.Context, sub string, scopes map[string]bool) (identity.AuthRecord, bool, error) {
	user, err := im.identifier.GetUserFromSubject(ctx, sub)
	if err != nil {
		im.logger.WithError(err).Errorln("IdentifierIdentityManager: identifier error")
		return nil, false, fmt.Errorf("IdentifierIdentityManager: identifier error")
	}

	if user == nil {
		return nil, false, fmt.Errorf("IdentifierIdentityManager: no user")
	}

	if user.Subject() != sub {
		return nil, false, fmt.Errorf("IdentifierIdentityManager: wrong user")
	}

	authorizedScopes, claims := authorizeScopes(user, scopes)

	auth := NewAuthRecord(sub, authorizedScopes, claims)
	auth.SetUser(user)

	return auth, true, nil
}

// ScopesSupported implements the identity.Manager interface.
func (im *IdentifierIdentityManager) ScopesSupported() []string {
	return []string{
		oidc.ScopeProfile,
		oidc.ScopeEmail,
		oidc.ScopeOfflineAccess,
		konnect.ScopeID,
	}
}

// ClaimsSupported implements the identity.Manager interface.
func (im *IdentifierIdentityManager) ClaimsSupported() []string {
	return []string{
		oidc.NameClaim,
		oidc.EmailClaim,
	}
}

// AddRoutes implements the identity.Manager interface.
func (im *IdentifierIdentityManager) AddRoutes(ctx context.Context, router *mux.Router) {
	im.identifier.AddRoutes(ctx, router)
}
