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
	"strings"

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

// TokenHandler implements the HTTP token endpoint for OpenID
// Connect 1.0 as specified at http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
func (p *Provider) TokenHandler(rw http.ResponseWriter, req *http.Request) {
	var err error
	var tr *payload.TokenRequest
	var found bool
	var ar *payload.AuthenticationRequest
	var auth identity.AuthRecord
	var accessTokenString string
	var idTokenString string
	var refreshTokenString string
	var approvedScopes map[string]bool
	var authorizedScopes map[string]bool

	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	// Validate request method
	switch req.Method {
	case http.MethodPost:
		// breaks
	default:
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, "request must be sent with POST")
		goto done
	}

	// Token Request Validation
	// http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation
	err = req.ParseForm()
	if err != nil {
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, err.Error())
		goto done
	}
	tr, err = payload.DecodeTokenRequest(req)
	if err != nil {
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, err.Error())
		goto done
	}

	err = tr.Validate(func(token *jwt.Token) (interface{}, error) {
		// Validator for incoming refresh tokens.
		// TODO(longsleep): Validate claims.
		return p.validateJWT(token)
	})
	if err != nil {
		goto done
	}

	switch tr.GrantType {
	case oidc.GrantTypeAuthorizationCode:
		ar, auth, found = p.codeManager.Pop(tr.Code)
		if !found {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "code not found")
			goto done
		}

		authorizedScopes = auth.AuthorizedScopes()

		// Additional validations according to https://tools.ietf.org/html/rfc6749#section-4.1.3
		// TODO(longsleep): Authenticate the client if client authentication is included.

		// Ensure that the authorization code was issued to the client id.
		if ar.ClientID != tr.ClientID {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "client_id mismatch")
			goto done
		}

		// Ensure that the "redirect_uri" parameter is a match.
		if ar.RawRedirectURI != tr.RawRedirectURI {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "redirect_uri mismatch")
			goto done
		}

	case oidc.GrantTypeRefreshToken:
		if tr.RefreshToken == nil {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "missing refresh_token")
			goto done
		}

		// Get claims from refresh token.
		claims := tr.RefreshToken.Claims.(*oidc.RefreshTokenClaims)

		// Ensure that the authorization code was issued to the client id.
		if claims.Audience != tr.ClientID {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "client_id mismatch")
			goto done
		}

		// Additional validations according to https://tools.ietf.org/html/rfc6749#section-4.1.3
		// TODO(longsleep): Authenticate the client if client authentication is included.
		// TODO(longsleep): Compare standard claims issuer.

		// Lookup Ref values from backend.
		approvedScopes, err = p.identityManager.ApprovedScopes(req.Context(), claims.Subject, tr.ClientID, claims.Ref)
		if err != nil {
			goto done
		}
		if approvedScopes == nil {
			// Use approvals from token if backend did not say anything.
			approvedScopes = make(map[string]bool)
			for _, scope := range claims.ApprovedScopesList {
				approvedScopes[scope] = true
			}
		}

		if len(tr.Scopes) > 0 {
			// Make sure all requested scopes are granted and limited authorized
			// scopes to the requested scopes.
			authorizedScopes = make(map[string]bool)
			for scope := range tr.Scopes {
				if !approvedScopes[scope] {
					err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InsufficientScope, "insufficient scope")
					goto done
				} else {
					authorizedScopes[scope] = true
				}
			}
		} else {
			// Authorize all approved scopes when no scopes are in request.
			authorizedScopes = approvedScopes
		}

		// Load user record from identitymanager, without any scopes.
		auth, found, err = p.identityManager.Fetch(req.Context(), claims.StandardClaims.Subject, nil)
		if !found {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "user not found")
			goto done
		}
		if err != nil {
			goto done
		}
		// Add authorized scopes.
		auth.AuthorizeScopes(authorizedScopes)

		// Create fake request for token generation.
		ar = &payload.AuthenticationRequest{
			ClientID: claims.Audience,
		}

	default:
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2UnsupportedGrantType, "grant_type value not implemented")
		goto done
	}

	// Create access token.
	accessTokenString, err = p.makeAccessToken(req.Context(), ar.ClientID, auth)
	if err != nil {
		goto done
	}

	switch tr.GrantType {
	case oidc.GrantTypeAuthorizationCode:
		// Create ID token when not previously requested.
		if !ar.ResponseTypes[oidc.ResponseTypeIDToken] {
			idTokenString, err = p.makeIDToken(req.Context(), ar, auth, accessTokenString, "")
			if err != nil {
				goto done
			}
		}

		// Create refresh token when granted.
		if authorizedScopes[oidc.ScopeOfflineAccess] {
			refreshTokenString, err = p.makeRefreshToken(req.Context(), ar.ClientID, auth)
			if err != nil {
				goto done
			}
		}
	}

done:
	if err != nil {
		switch err.(type) {
		case *oidc.OAuth2Error:
			err = writeJSON(rw, http.StatusBadRequest, err, "application/json")
			if err != nil {
				p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
			}
		default:
			p.ErrorPage(rw, http.StatusInternalServerError, err.Error(), "well sorry, but there was a problem")
		}

		return
	}

	// Successful Token Response
	// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
	response := &payload.TokenSuccess{}
	if accessTokenString != "" {
		response.AccessToken = accessTokenString
		response.TokenType = oidc.TokenTypeBearer
		response.ExpiresIn = int64(p.accessTokenDuration.Seconds())
	}
	if idTokenString != "" {
		response.IDToken = idTokenString
	}
	if refreshTokenString != "" {
		response.RefreshToken = refreshTokenString
	}

	err = writeJSON(rw, http.StatusOK, response, "application/json")
	if err != nil {
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
	}
}

// UserInfoHandler implements the HTTP userinfo endpoint for OpenID
// Connect 1.0 as specified at https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func (p *Provider) UserInfoHandler(rw http.ResponseWriter, req *http.Request) {
	var err error
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	switch req.Method {
	case http.MethodOptions:
		rw.WriteHeader(http.StatusOK)
		return
	case http.MethodHead:
		fallthrough
	case http.MethodPost:
		fallthrough
	case http.MethodGet:
		// pass
	default:
		return
	}

	var claims *oidc.AccessTokenClaims

	// Parse and validate UserInfo request
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest

	auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	switch auth[0] {
	case oidc.TokenTypeBearer:
		if len(auth) != 2 {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, "Invalid Bearer authorization header format")
			break
		}
		claims = &oidc.AccessTokenClaims{}
		_, err = jwt.ParseWithClaims(auth[1], claims, func(token *jwt.Token) (interface{}, error) {
			return p.validateJWT(token)
		})
		if err == nil {
			// TODO(longsleep): Validate all claims.
			err = claims.Valid()
		}
		if err != nil {
			// Wrap as OAuth2 error.
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidToken, err.Error())
		}

	default:
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, "Bearer authorization required")
	}
	if err != nil {
		oidc.WriteWWWAuthenticateError(rw, http.StatusUnauthorized, err)
		return
	}

	var user identity.AuthRecord
	var found bool
	user, found, err = p.identityManager.Fetch(req.Context(), claims.StandardClaims.Subject, claims.AuthorizedScopes())
	if !found {
		p.ErrorPage(rw, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		oidc.WriteWWWAuthenticateError(rw, http.StatusUnauthorized, oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidToken, err.Error()))
		return
	}

	response := &payload.UserInfoResponse{
		UserInfoClaims: oidc.UserInfoClaims{
			Subject: user.UserID(),
		},
		ProfileClaims: oidc.NewProfileClaims(user.Claims(oidc.ScopeProfile)[0]),
		EmailClaims:   oidc.NewEmailClaims(user.Claims(oidc.ScopeEmail)[0]),
	}

	err = writeJSON(rw, http.StatusOK, response, "application/json")
	if err != nil {
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
	}
}
