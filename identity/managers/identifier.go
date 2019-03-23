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
	"strings"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/identifier"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/identity/clients"
	"stash.kopano.io/kc/konnect/managers"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/utils"
)

// IdentifierIdentityManager implements an identity manager which relies on
// Konnect its identifier to provide identity.
type IdentifierIdentityManager struct {
	signInFormURI string
	signedOutURI  string

	scopesSupported []string
	claimsSupported []string

	identifier *identifier.Identifier
	clients    *clients.Registry
	logger     logrus.FieldLogger
}

type identifierUser struct {
	*identifier.IdentifiedUser
}

func (u *identifierUser) Raw() string {
	return u.IdentifiedUser.Subject()
}

func (u *identifierUser) Subject() string {
	sub, _ := getPublicSubject([]byte(u.Raw()), []byte(u.IdentifiedUser.BackendName()))
	return sub
}

func asIdentifierUser(user *identifier.IdentifiedUser) *identifierUser {
	return &identifierUser{user}
}

// NewIdentifierIdentityManager creates a new IdentifierIdentityManager from the provided
// parameters.
func NewIdentifierIdentityManager(c *identity.Config, i *identifier.Identifier) *IdentifierIdentityManager {
	im := &IdentifierIdentityManager{
		signInFormURI: c.SignInFormURI.String(),
		signedOutURI:  c.SignedOutURI.String(),

		scopesSupported: setupSupportedScopes([]string{
			oidc.ScopeOfflineAccess,
		}, i.ScopesSupported(), c.ScopesSupported),
		claimsSupported: []string{
			oidc.NameClaim,
			oidc.FamilyNameClaim,
			oidc.GivenNameClaim,
			oidc.EmailClaim,
			oidc.EmailVerifiedClaim,
		},

		identifier: i,
		logger:     c.Logger,
	}

	return im
}

// RegisterManagers registers the provided managers,
func (im *IdentifierIdentityManager) RegisterManagers(mgrs *managers.Managers) error {
	im.clients = mgrs.Must("clients").(*clients.Registry)

	return im.identifier.RegisterManagers(mgrs)
}

// Authenticate implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, next identity.Manager) (identity.AuthRecord, error) {
	var user *identifierUser
	var err error

	u, _ := im.identifier.GetUserFromLogonCookie(ctx, req, ar.MaxAge, true)
	if u != nil {
		// TODO(longsleep): Add other user meta data.
		user = asIdentifierUser(u)
	} else {
		// Not signed in.
		if next != nil {
			// Give next handler a chance if any.
			if auth, err := next.Authenticate(ctx, rw, req, ar, nil); err == nil {
				// Inner handler success.
				// TODO(longsleep): Add check and option to avoid that the inner
				// handler can ever return users which exist at the outer.
				return auth, err
			} else {
				switch err.(type) {
				case *payload.AuthenticationError:
					// ignore, breaks
				case *identity.LoginRequiredError:
					// ignore, breaks
				case *identity.IsHandledError:
					// breaks, breaks
				default:
				}
				im.logger.WithFields(utils.ErrorAsFields(err)).Errorln("inner authorize request failed")
			}
		}
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

	// More checks.
	if err == nil {
		var sub string
		if user != nil {
			sub = user.Subject()
		}
		err = ar.Verify(sub)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		// Build login URL.
		query, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		query.Set("flow", identifier.FlowOIDC)
		if ar.Claims != nil {
			// Add derived scope list from claims request.
			claimsScopes := ar.Claims.Scopes(ar.Scopes)
			if len(claimsScopes) > 0 {
				query.Set("claims_scope", strings.Join(claimsScopes, " "))
			}
		}
		u, _ := url.Parse(im.signInFormURI)
		u.RawQuery = query.Encode()
		utils.WriteRedirect(rw, http.StatusFound, u, nil, false)

		return nil, &identity.IsHandledError{}
	}

	auth := identity.NewAuthRecord(im, user.Subject(), nil, nil, nil)
	auth.SetUser(user)
	if loggedOn, logonAt := u.LoggedOn(); loggedOn {
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

	origin := ""
	if false {
		// TODO(longsleep): find a condition when this can be enabled.
		origin = utils.OriginFromRequestHeaders(req.Header)
	}
	clientDetails, err := im.clients.Lookup(req.Context(), ar.ClientID, "", ar.RedirectURI, origin, true)
	if err != nil {
		return nil, ar.NewError(oidc.ErrorOAuth2AccessDenied, err.Error())
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
		filteredApprovedScopes, allApprovedScopes := consent.Scopes(ar.Scopes)

		// Filter claims request by approved scopes.
		if ar.Claims != nil {
			err = ar.Claims.ApplyScopes(allApprovedScopes)
			if err != nil {
				return nil, err
			}
		}

		approvedScopes = filteredApprovedScopes
	}

	if promptConsent {
		if ar.Prompts[oidc.PromptNone] == true {
			return auth, ar.NewError(oidc.ErrorOIDCInteractionRequired, "consent required")
		}

		// Build consent URL.
		query, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		query.Set("flow", identifier.FlowConsent)
		if ar.Claims != nil {
			// Add derived scope list from claims request.
			claimsScopes := ar.Claims.Scopes(ar.Scopes)
			if len(claimsScopes) > 0 {
				query.Set("claims_scope", strings.Join(claimsScopes, " "))
			}
		}
		u, _ := url.Parse(im.signInFormURI)
		u.RawQuery = query.Encode()
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
	auth.AuthorizeClaims(ar.Claims)
	return auth, nil
}

// EndSession implements the identity.Manager interface.
func (im *IdentifierIdentityManager) EndSession(ctx context.Context, rw http.ResponseWriter, req *http.Request, esr *payload.EndSessionRequest) error {
	// FIXME(longsleep): For now we always require the id_token_hint. Instead
	// of fail we should treat is as unstrusted client.
	if esr.IDTokenHint == nil {
		im.logger.Debugln("endsession request without id_token_hint")
		return esr.NewBadRequest(oidc.ErrorOAuth2InvalidRequest, "id_token_hint required")
	}

	origin := utils.OriginFromRequestHeaders(req.Header)
	claims := esr.IDTokenHint.Claims.(*oidc.IDTokenClaims)
	clientDetails, err := im.clients.Lookup(ctx, claims.Audience, "", esr.PostLogoutRedirectURI, origin, true)
	if err != nil {
		// FIXME(longsleep): This error should no be fatal since according to
		// the spec in https://openid.net/specs/openid-connect-session-1_0.html#RPLogout the
		// id_token_hint is not enforced to match the audience. Instead of fail
		// we should treat it as untrusted client.
		im.logger.WithError(err).Errorln("IdentifierIdentityManager: id_token_hint does not match request")
		return esr.NewBadRequest(oidc.ErrorOAuth2InvalidRequest, "id_token_hint does not match request")
	}

	var user *identifierUser
	u, _ := im.identifier.GetUserFromLogonCookie(ctx, req, 0, false)
	if u != nil {
		user = asIdentifierUser(u)
	} else {
		// Ignore when not signed in, for end session.
	}

	// More checks.
	if err == nil {
		var sub string
		if user != nil {
			sub = user.Subject()
		}
		err = esr.Verify(sub)
		if err != nil {
			return err
		}
	}

	if clientDetails.Trusted {
		// Directly clear identifier session when a trusted client requests it.
		err = im.identifier.UnsetLogonCookie(ctx, u, rw)
		if err != nil {
			im.logger.WithError(err).Errorln("IdentifierIdentityManager: failed to unset logon cookie")
			return err
		}
	}

	if !clientDetails.Trusted || esr.PostLogoutRedirectURI == nil || esr.PostLogoutRedirectURI.String() == "" {
		// Handle directly.by redirecting to our logout confirm url for untrusted
		// clients or when no URL was set.
		u, _ := url.Parse(im.signedOutURI)
		u.RawQuery = fmt.Sprintf("flow=%s", identifier.FlowOIDC)
		return identity.NewRedirectError(oidc.ErrorOIDCInteractionRequired, u)
	}

	return nil
}

// ApproveScopes implements the Backend interface.
func (im *IdentifierIdentityManager) ApproveScopes(ctx context.Context, sub string, audience string, approvedScopes map[string]bool) (string, error) {
	ref := rndm.GenerateRandomString(32)

	// TODO(longsleep): Store generated ref with provided data.
	return ref, nil
}

// ApprovedScopes implements the Backend interface.
func (im *IdentifierIdentityManager) ApprovedScopes(ctx context.Context, sub string, audience string, ref string) (map[string]bool, error) {
	if ref == "" {
		return nil, fmt.Errorf("IdentifierIdentityManager: invalid ref")
	}

	return nil, nil
}

// Fetch implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Fetch(ctx context.Context, userID string, sessionRef *string, scopes map[string]bool, requestedClaimsMaps []*payload.ClaimsRequestMap) (identity.AuthRecord, bool, error) {
	u, err := im.identifier.GetUserFromID(ctx, userID, sessionRef)
	if err != nil {
		im.logger.WithError(err).Errorln("IdentifierIdentityManager: fetch failed to get user from userID")
		return nil, false, fmt.Errorf("IdentifierIdentityManager: identifier error")
	}

	if u == nil {
		return nil, false, fmt.Errorf("IdentifierIdentityManager: no user")
	}

	user := asIdentifierUser(u)
	authorizedScopes, _ := identity.AuthorizeScopes(im, user, scopes)
	claims := identity.GetUserClaimsForScopes(user, authorizedScopes, requestedClaimsMaps)

	auth := identity.NewAuthRecord(im, user.Subject(), authorizedScopes, nil, claims)
	auth.SetUser(user)

	return auth, true, nil
}

// Name implements the identity.Manager interface.
func (im *IdentifierIdentityManager) Name() string {
	return im.identifier.Name()
}

// ScopesSupported implements the identity.Manager interface.
func (im *IdentifierIdentityManager) ScopesSupported(scopes map[string]bool) []string {
	return im.scopesSupported
}

// ClaimsSupported implements the identity.Manager interface.
func (im *IdentifierIdentityManager) ClaimsSupported(claims []string) []string {
	return im.claimsSupported
}

// AddRoutes implements the identity.Manager interface.
func (im *IdentifierIdentityManager) AddRoutes(ctx context.Context, router *mux.Router) {
	im.identifier.AddRoutes(ctx, router)
}

// OnSetLogon implements the identity.Manager interface.
func (im *IdentifierIdentityManager) OnSetLogon(cb func(ctx context.Context, rw http.ResponseWriter, user identity.User) error) error {
	return im.identifier.OnSetLogon(cb)
}

// OnUnsetLogon implements the identity.Manager interface.
func (im *IdentifierIdentityManager) OnUnsetLogon(cb func(ctx context.Context, rw http.ResponseWriter) error) error {
	return im.identifier.OnUnsetLogon(cb)
}
