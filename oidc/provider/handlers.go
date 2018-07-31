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

	"github.com/dgrijalva/jwt-go"
	jwk "github.com/mendsley/gojwk"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/utils"
)

// WellKnownHandler implements the HTTP provider configuration endpoint
// for OpenID Connect 1.0 as specified at https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (p *Provider) WellKnownHandler(rw http.ResponseWriter, req *http.Request) {
	// TODO(longsleep): Add caching headers.
	wellKnown := p.metadata

	err := utils.WriteJSON(rw, http.StatusOK, wellKnown, "")
	if err != nil {
		p.logger.WithError(err).Errorln("well-known request failed writing response")
	}
}

// JwksHandler implements the HTTP provider JWKS endpoint for OpenID provider
// metadata used with OpenID Connect Discovery 1.0 as specified at https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
func (p *Provider) JwksHandler(rw http.ResponseWriter, req *http.Request) {
	// TODO(longsleep): Add caching headers.
	// TODO(longsleep): Use better library, or self implemented jwks struct.
	jwks := &jwk.Key{
		Keys: make([]*jwk.Key, len(p.validationKeys)-1),
	}
	for kid, key := range p.validationKeys {
		keyJwk, err := jwk.PublicKey(key)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		keyJwk.Use = "sig" // https://tools.ietf.org/html/rfc7517#section-4.2
		keyJwk.Kid = kid
		jwks.Keys = append(jwks.Keys, keyJwk)
	}

	err := utils.WriteJSON(rw, http.StatusOK, jwks, "application/jwk-set+json")
	if err != nil {
		p.logger.WithError(err).Errorln("jwks request failed writing response")
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

	addResponseHeaders(rw.Header())

	// OpenID Connect 1.0 authentication request validation.
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitValidation
	err = req.ParseForm()
	if err != nil {
		p.logger.WithError(err).Errorln("authorize request invalid form data")
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}

	ar, err := payload.DecodeAuthenticationRequest(req, p.metadata)
	if err != nil {
		p.logger.WithError(err).Errorln("authorize request invalid request data")
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}
	err = ar.Validate(func(token *jwt.Token) (interface{}, error) {
		// Validator for incoming IDToken hints, looks up key.
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
		case *identity.LoginRequiredError:
			p.LoginRequiredPage(rw, req, err.(*identity.LoginRequiredError).SignInURI())
		case *identity.IsHandledError:
			// do nothing
		case *oidc.OAuth2Error:
			err = ar.NewError(err.Error(), err.(*oidc.OAuth2Error).Description())
			p.Found(rw, ar.RedirectURI, err, ar.UseFragment)
		default:
			p.logger.WithFields(utils.ErrorAsFields(err)).Errorln("authorize request failed")
			p.ErrorPage(rw, http.StatusInternalServerError, err.Error(), "well sorry, but there was a problem")
		}

		return
	}

	authorizedScopesList := makeArrayFromBoolMap(authorizedScopes)

	// Successful Authentication Response
	// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthResponse
	response := &payload.AuthenticationSuccess{
		State: ar.State,
		Scope: strings.Join(authorizedScopesList, " "),
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
	tr, err = payload.DecodeTokenRequest(req, p.metadata)
	if err != nil {
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, err.Error())
		goto done
	}

	err = tr.Validate(func(token *jwt.Token) (interface{}, error) {
		// Validator for incoming refresh tokens, looks up key.
		return p.validateJWT(token)
	}, &konnect.RefreshTokenClaims{})
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
		claims := tr.RefreshToken.Claims.(*konnect.RefreshTokenClaims)

		// Ensure that the authorization code was issued to the client id.
		if claims.Audience != tr.ClientID {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidGrant, "client_id mismatch")
			goto done
		}

		// Additional validations according to https://tools.ietf.org/html/rfc6749#section-4.1.3
		// TODO(longsleep): Authenticate the client if client authentication is included.
		// TODO(longsleep): Compare standard claims issuer.

		ctx := konnect.NewClaimsContext(req.Context(), claims)

		// Lookup Ref values from backend.
		approvedScopes, err = p.identityManager.ApprovedScopes(ctx, claims.Subject, tr.ClientID, claims.Ref)
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
		auth, found, err = p.identityManager.Fetch(ctx, claims.StandardClaims.Subject, nil)
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
			err = utils.WriteJSON(rw, http.StatusBadRequest, err, "")
			if err != nil {
				p.logger.WithError(err).Errorln("token request failed writing response")
				return
			}
		default:
			p.logger.WithFields(utils.ErrorAsFields(err)).Errorln("token request failed")
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

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		p.logger.WithError(err).Errorln("token request failed writing response")
	}
}

// UserInfoHandler implements the HTTP userinfo endpoint for OpenID
// Connect 1.0 as specified at https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
func (p *Provider) UserInfoHandler(rw http.ResponseWriter, req *http.Request) {
	var err error
	addResponseHeaders(rw.Header())

	switch req.Method {
	case http.MethodHead:
		fallthrough
	case http.MethodPost:
		fallthrough
	case http.MethodGet:
		// pass
	default:
		return
	}

	// Parse and validate UserInfo request
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest

	claims, err := p.GetAccessTokenClaimsFromRequest(req)
	if err != nil {
		p.logger.WithFields(utils.ErrorAsFields(err)).Debugln("userinfo request unauthorized")
		oidc.WriteWWWAuthenticateError(rw, http.StatusUnauthorized, err)
		return
	}

	ctx := konnect.NewClaimsContext(req.Context(), claims)

	var auth identity.AuthRecord
	var found bool
	auth, found, err = p.identityManager.Fetch(ctx, claims.StandardClaims.Subject, claims.AuthorizedScopes())
	if !found {
		p.logger.WithField("sub", claims.StandardClaims.Subject).Debugln("userinfo request user not found")
		p.ErrorPage(rw, http.StatusNotFound, "", "user not found")
		return
	}
	if err != nil {
		p.logger.WithFields(utils.ErrorAsFields(err)).Debugln("userinfo request invalid token")
		oidc.WriteWWWAuthenticateError(rw, http.StatusUnauthorized, oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidToken, err.Error()))
		return
	}

	publicSubject, err := p.PublicSubjectFromAuth(auth)
	if err != nil {
		p.logger.WithFields(utils.ErrorAsFields(err)).Debugln("userinfo request failed to create subject")
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
		return
	}

	response := &konnect.UserInfoResponse{
		UserInfoResponse: &payload.UserInfoResponse{
			UserInfoClaims: oidc.UserInfoClaims{
				Subject: publicSubject,
			},
			ProfileClaims: oidc.NewProfileClaims(auth.Claims(oidc.ScopeProfile)[0]),
			EmailClaims:   oidc.NewEmailClaims(auth.Claims(oidc.ScopeEmail)[0]),
		},
	}

	// Helper to receive user from auth, but only once.
	withUser := func() func() identity.User {
		var u identity.User
		var fetched bool
		return func() identity.User {
			if !fetched {
				fetched = true
				u = auth.User()
			}
			return u
		}
	}()
	authorizedScopes := auth.AuthorizedScopes()
	var user identity.User

	// Include additional Konnect specific claims when corresponding scopes are authorized.
	if ok, _ := authorizedScopes[konnect.ScopeID]; ok {
		user = withUser()
		if userWithID, ok := user.(identity.UserWithID); ok {
			claims := &konnect.IDClaims{
				KCID: userWithID.ID(),
			}
			if userWithUsername, ok := user.(identity.UserWithUsername); ok {
				claims.KCIDUsername = userWithUsername.Username()
			}
			if claims.KCIDUsername == "" {
				claims.KCIDUsername = user.Subject()
			}

			response.IDClaims = claims
		}
	}
	if ok, _ := authorizedScopes[konnect.ScopeUniqueUserID]; ok {
		user = withUser()
		if userWithUniqueID, ok := user.(identity.UserWithUniqueID); ok {
			claims := &konnect.UniqueUserIDClaims{
				KCUniqueUserID: userWithUniqueID.UniqueID(),
			}

			response.UniqueUserIDClaims = claims
		}
	}

	// Create a map so additional user specific claims can be added.
	responseAsMap, err := payload.ToMap(response)
	if err != nil {
		p.logger.WithFields(utils.ErrorAsFields(err)).Debugln("userinfo request failed to encode claims")
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
		return
	}

	// Inject extra claims.
	extraClaims := auth.Claims("")[0]
	if extraClaims != nil {
		if extraClaimsMap, ok := extraClaims.(jwt.MapClaims); ok {
			for claim, value := range extraClaimsMap {
				responseAsMap[claim] = value
			}
		}
	}

	err = utils.WriteJSON(rw, http.StatusOK, responseAsMap, "")
	if err != nil {
		p.logger.WithError(err).Errorln("userinfo request failed writing response")
	}
}

// EndSessionHandler implements the HTTP endpoint for RP initiated logout with
// OpenID Connect Session Management 1.0 as specified at
// https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
func (p *Provider) EndSessionHandler(rw http.ResponseWriter, req *http.Request) {
	var err error

	addResponseHeaders(rw.Header())

	// Validate request.
	err = req.ParseForm()
	if err != nil {
		p.logger.WithError(err).Errorln("endsession request invalid form data")
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}

	esr, err := payload.DecodeEndSessionRequest(req, p.metadata)
	if err != nil {
		p.logger.WithError(err).Errorln("endsession request invalid request data")
		p.ErrorPage(rw, http.StatusBadRequest, oidc.ErrorOAuth2InvalidRequest, err.Error())
		return
	}
	err = esr.Validate(func(token *jwt.Token) (interface{}, error) {
		// Validator for incoming IDToken hints, looks up key.
		return p.validateJWT(token)
	})
	if err != nil {
		goto done
	}

	// Authorization unauthenticates end user.
	err = p.identityManager.EndSession(req.Context(), rw, req, esr)
	if err != nil {
		goto done
	}

done:
	if err != nil {
		switch err.(type) {
		case *payload.AuthenticationBadRequest:
			p.ErrorPage(rw, http.StatusBadRequest, err.Error(), err.(*payload.AuthenticationBadRequest).Description())
		case *identity.RedirectError:
			p.Found(rw, err.(*identity.RedirectError).RedirectURI(), nil, false)
		case *identity.IsHandledError:
			// do nothing
		case *oidc.OAuth2Error:
			err = esr.NewError(err.Error(), err.(*oidc.OAuth2Error).Description())
			if esr.PostLogoutRedirectURI == nil || esr.PostLogoutRedirectURI.String() == "" {
				p.ErrorPage(rw, http.StatusForbidden, err.Error(), "oauth2 error")
			} else {
				p.Found(rw, esr.PostLogoutRedirectURI, err, false)
			}
		default:
			p.logger.WithFields(utils.ErrorAsFields(err)).Errorln("endsession request failed")
			p.ErrorPage(rw, http.StatusInternalServerError, err.Error(), "well sorry, but there was a problem")
		}

		return
	}

	// EndSession Response.
	response := &payload.AuthenticationSuccess{
		State: esr.State,
	}

	if esr.PostLogoutRedirectURI == nil || esr.PostLogoutRedirectURI.String() == "" {
		err = utils.WriteJSON(rw, http.StatusOK, response, "")
		if err != nil {
			p.logger.WithError(err).Errorln("endsession request failed writing response")
		}
	} else {
		p.Found(rw, esr.PostLogoutRedirectURI, response, false)
	}
}
