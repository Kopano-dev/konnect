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

package provider

import (
	"context"
	"net/http"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"

	"github.com/dgrijalva/jwt-go"
)

// WellKnownHandler implements the HTTP provider configuration endpoint
// for OpenID Connect 1.0 as specified at https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (p *Provider) WellKnownHandler(rw http.ResponseWriter, req *http.Request) {
	// TODO(longsleep): Add caching headers.
	// Create well known.
	wellKnown := &payload.WellKnown{
		Issuer:                p.issuerIdentifier,
		AuthorizationEndpoint: p.makeIssURL(p.authorizationPath),
		TokenEndpoint:         p.makeIssURL(p.tokenPath),
		UserInfoEndpoint:      p.makeIssURL(p.userInfoPath),
		JwksURI:               p.makeIssURL(p.jwksPath),
		ScopesSupported: uniqueStrings(append([]string{
			oidc.ScopeOpenID,
		}, p.identityManager.ScopesSupported()...)),
		ResponseTypesSupported: []string{
			oidc.ResponseTypeIDTokenToken,
			oidc.ResponseTypeIDToken,
		},
		SubjectTypesSupported: []string{
			oidc.SubjectIDPublic,
		},
		ClaimsSupported: uniqueStrings(append([]string{
			oidc.IssuerIdentifierClaim,
			oidc.SubjectIdentifierClaim,
			oidc.AudienceClaim,
			oidc.ExpirationClaim,
			oidc.IssuedAtClaim,
		}, p.identityManager.ClaimsSupported()...)),
	}
	if p.signingMethod != nil {
		wellKnown.IDTokenSigningAlgValuesSupported = []string{
			p.signingMethod.Alg(),
		}
	}

	err := writeJSON(rw, http.StatusOK, wellKnown, "application/json")
	if err != nil {
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
	}
}

// AuthorizeHandler implements the HTTP authorization endpoint for OpenID
// Connect 1.0 as specified at http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthorizationEndpoint
//
// Currently AuthorizeHandler implements only the Implicit Flow as specified at
// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
func (p *Provider) AuthorizeHandler(rw http.ResponseWriter, req *http.Request) {
	var err error
	var auth identity.AuthRecord

	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	// OpenID Connect 1.0 authentication request validation.
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitValidation
	err = req.ParseForm()
	if err != nil {
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}

	ar, err := payload.DecodeAuthenticationRequest(req)
	if err != nil {
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}
	err = ar.Validate(func(token *jwt.Token) (interface{}, error) {
		// Validator for incoming IDToken hints.
		// TODO(longsleep): Validate claims.
		return p.validateJWT(token)
	})
	if err != nil {
		goto done
	}

	// Authorization Server Authenticates End-User
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthenticates
	auth, err = p.identityManager.Authenticate(req.Context(), rw, req, ar)
	if err != nil {
		goto done
	}

	// Authorization Server Obtains End-User Consent/Authorization
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitConsent
	auth, err = p.identityManager.Authorize(req.Context(), rw, req, ar, auth)
	if err != nil {
		goto done
	}

done:
	p.AuthorizeResponse(rw, req, ar, auth, err)
}

// AuthorizeResponse writes the result according to the provided parameters to
// the provided http.ResponseWriter.
func (p *Provider) AuthorizeResponse(rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord, err error) {
	var codeString string
	var accessTokenString string
	var idTokenString string
	var authorizedScopes map[string]bool
	var ctx context.Context

	if err != nil {
		goto done
	}

	ctx = identity.NewContext(req.Context(), auth)

	authorizedScopes = auth.AuthorizedScopes()

	// Create code when requested.
	if _, ok := ar.ResponseTypes[oidc.ResponseTypeCode]; ok {
		codeString, err = p.codeManager.Create(ar, auth)
		if err != nil {
			goto done
		}
	}

	// Create access token when requested.
	if _, ok := ar.ResponseTypes[oidc.ResponseTypeToken]; ok {
		accessTokenString, err = p.makeAccessToken(ctx, ar.ClientID, auth)
		if err != nil {
			goto done
		}
	}

	// Create ID token when requested and granted.
	if authorizedScopes[oidc.ScopeOpenID] {
		if _, ok := ar.ResponseTypes[oidc.ResponseTypeIDToken]; ok {
			idTokenString, err = p.makeIDToken(ctx, ar, auth, accessTokenString, codeString)
			if err != nil {
				goto done
			}
		}
	}

done:
	if err != nil {
		switch err.(type) {
		case *payload.AuthenticationError:
			p.Found(rw, ar.RedirectURI, err, ar.UseFragment)
		case *payload.AuthenticationBadRequest:
			p.ErrorPage(rw, http.StatusBadRequest, err.Error(), err.(*payload.AuthenticationBadRequest).Description())
		case *identity.RedirectError:
			p.Found(rw, err.(*identity.RedirectError).RedirectURI(), nil, false)
		case *identity.IsHandledError:
			// do nothing
		case *oidc.OAuth2Error:
			err = ar.NewError(err.Error(), err.(*oidc.OAuth2Error).Description())
			p.Found(rw, ar.RedirectURI, err, ar.UseFragment)
		default:
			p.ErrorPage(rw, http.StatusInternalServerError, err.Error(), "well sorry, but there was a problem")
		}

		return
	}

	// Successful Authentication Response
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
	response := &payload.AuthenticationSuccess{
		State: ar.State,
	}
	if codeString != "" {
		response.Code = codeString
	}
	if accessTokenString != "" {
		response.AccessToken = accessTokenString
		response.TokenType = oidc.TokenTypeBearer
		response.ExpiresIn = int64(p.accessTokenDuration.Seconds())
	}
	if idTokenString != "" {
		response.IDToken = idTokenString
	}

	p.Found(rw, ar.RedirectURI, response, ar.UseFragment)
}
