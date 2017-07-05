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
	"net/http"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"

	"github.com/dgrijalva/jwt-go"
)

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

	if p.identityManager == nil {
		p.ErrorPage(rw, http.StatusInternalServerError, oidc.ErrorOIDCRequestNotSupported, "no identity manager")
		return
	}

	// Authorization Server Authenticates End-User
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthenticates
	auth, err = p.identityManager.Authenticate(rw, req, ar)
	if err != nil {
		goto done
	}

	// Authorization Server Obtains End-User Consent/Authorization
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitConsent
	auth, err = p.identityManager.Authorize(rw, req, ar, auth)
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

	if err != nil {
		goto done
	}

	authorizedScopes = auth.AuthorizedScopes()

	// Create code when requested.
	if _, ok := ar.ResponseTypes[oidc.ResponseTypeCode]; ok {
		err = ar.NewError(oidc.ErrorOAuth2UnsupportedResponseType, "code flow not implemented")
		goto done
	}

	// Create access token when requested.
	if _, ok := ar.ResponseTypes[oidc.ResponseTypeToken]; ok {
		accessTokenString, err = p.makeAccessToken(req.Context(), ar.ClientID, auth)
		if err != nil {
			goto done
		}
	}

	// Create ID token when requested and granted.
	if authorizedScopes[oidc.ScopeOpenID] {
		if _, ok := ar.ResponseTypes[oidc.ResponseTypeIDToken]; ok {
			idTokenString, err = p.makeIDToken(req.Context(), ar, auth, accessTokenString, codeString)
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
