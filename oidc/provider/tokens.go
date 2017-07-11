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
	"fmt"
	"time"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"

	"github.com/dgrijalva/jwt-go"
)

func (p *Provider) makeAccessToken(ctx context.Context, audience string, auth identity.AuthRecord) (string, error) {
	authorizedScopesList := []string{}
	for scope, granted := range auth.AuthorizedScopes() {
		if granted {
			authorizedScopesList = append(authorizedScopesList, scope)
		}
	}
	accessTokenClaims := konnect.AccessTokenClaims{
		IsAccessToken:        true,
		AuthorizedScopesList: authorizedScopesList,
		StandardClaims: jwt.StandardClaims{
			Issuer:    p.issuerIdentifier,
			Subject:   auth.Subject(),
			Audience:  audience,
			ExpiresAt: time.Now().Add(p.accessTokenDuration).Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	user := auth.User()
	if user != nil {
		if userWithClaims, ok := user.(identity.UserWithClaims); ok {
			accessTokenClaims.IdentityClaims = userWithClaims.Claims()
		}
	}

	accessToken := jwt.NewWithClaims(p.signingMethod, accessTokenClaims)
	accessToken.Header[oidc.JWTHeaderKeyID] = p.signingKeyID

	return accessToken.SignedString(p.signingKey)
}

func (p *Provider) makeIDToken(ctx context.Context, ar *payload.AuthenticationRequest, auth identity.AuthRecord, accessTokenString string, codeString string) (string, error) {
	idTokenClaims := &oidc.IDTokenClaims{
		Nonce: ar.Nonce,
		StandardClaims: jwt.StandardClaims{
			Issuer:    p.issuerIdentifier,
			Subject:   auth.Subject(),
			Audience:  ar.ClientID,
			ExpiresAt: time.Now().Add(time.Hour).Unix(), // 1 Hour, must be consumed by then.
			IssuedAt:  time.Now().Unix(),
		}}
	if accessTokenString == "" {
		// Include requested scope data in ID token when no access token is
		// generated.
		user, found, err := p.identityManager.Fetch(ctx, auth.Subject(), auth.AuthorizedScopes())
		if !found {
			return "", fmt.Errorf("user not found")
		}
		if err != nil {
			return "", err
		}

		if _, ok := ar.Scopes[oidc.ScopeProfile]; ok {
			idTokenClaims.ProfileClaims = oidc.NewProfileClaims(user.Claims(oidc.ScopeProfile)[0])
		}
		if _, ok := ar.Scopes[oidc.ScopeEmail]; ok {
			idTokenClaims.EmailClaims = oidc.NewEmailClaims(user.Claims(oidc.ScopeEmail)[0])
		}
	} else {
		// Add left-most hash of access token.
		// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken
		hash, err := oidc.HashFromSigningMethod(p.signingMethod.Alg())
		if err != nil {
			return "", err
		}

		idTokenClaims.AccessTokenHash = oidc.LeftmostHash([]byte(accessTokenString), hash).String()
	}
	if codeString != "" {
		// Add left-most hash of code.
		// http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
		hash, err := oidc.HashFromSigningMethod(p.signingMethod.Alg())
		if err != nil {
			return "", err
		}

		idTokenClaims.CodeHash = oidc.LeftmostHash([]byte(codeString), hash).String()
	}

	idToken := jwt.NewWithClaims(p.signingMethod, idTokenClaims)
	idToken.Header[oidc.JWTHeaderKeyID] = p.signingKeyID

	return idToken.SignedString(p.signingKey)
}

func (p *Provider) makeRefreshToken(ctx context.Context, audience string, auth identity.AuthRecord) (string, error) {
	approvedScopesList := []string{}
	approvedScopes := make(map[string]bool)
	for scope, granted := range auth.AuthorizedScopes() {
		if granted {
			approvedScopesList = append(approvedScopesList, scope)
			approvedScopes[scope] = true
		}
	}

	ref, err := p.identityManager.ApproveScopes(ctx, auth.Subject(), audience, approvedScopes)
	if err != nil {
		return "", err
	}

	refreshTokenClaims := &konnect.RefreshTokenClaims{
		IsRefreshToken:     true,
		ApprovedScopesList: approvedScopesList,
		Ref:                ref,
		StandardClaims: jwt.StandardClaims{
			Issuer:    p.issuerIdentifier,
			Subject:   auth.Subject(),
			Audience:  audience,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 365 * 3).Unix(), // 3 Years.
			IssuedAt:  time.Now().Unix(),
		},
	}

	refreshToken := jwt.NewWithClaims(p.signingMethod, refreshTokenClaims)
	refreshToken.Header[oidc.JWTHeaderKeyID] = p.signingKeyID

	return refreshToken.SignedString(p.signingKey)
}

func (p *Provider) validateJWT(token *jwt.Token) (interface{}, error) {
	rawAlg, ok := token.Header[oidc.JWTHeaderAlg]
	if !ok {
		return nil, fmt.Errorf("No alg header")
	}
	alg, ok := rawAlg.(string)
	if !ok {
		return nil, fmt.Errorf("Invalid alg value")
	}
	if alg != p.signingMethod.Alg() {
		return nil, fmt.Errorf("Unexpected alg value")
	}
	rawKid, ok := token.Header[oidc.JWTHeaderKeyID]
	if !ok {
		return nil, fmt.Errorf("No kid header")
	}
	kid, ok := rawKid.(string)
	if !ok {
		return nil, fmt.Errorf("Invalid kid value")
	}
	key, ok := p.validationKeys[kid]
	if !ok {
		return nil, fmt.Errorf("Unknown kid")
	}
	return key, nil
}
