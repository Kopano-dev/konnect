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

package oidc

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// Standard claims as used in JSON Web Tokens.
const (
	IssuerIdentifierClaim  = "iss"
	SubjectIdentifierClaim = "sub"
	AudienceClaim          = "aud"
	ExpirationClaim        = "exp"
	IssuedAtClaim          = "iat"
)

// Additional claims supported by Konnect and defined by OIDC.
const (
	NameClaim          = "name"
	EmailClaim         = "email"
	EmailVerifiedClaim = "email_verified"
)

// Access token claims used by Konnect.
const (
	IsAccessTokenClaim    = "kc.isAccessToken"
	AuthorizedScopesClaim = "kc.authorizedScopes"
	IsRefreshTokenClaim   = "kc.isRefreshToken"
	RefClaim              = "kc.ref"
)

// IDTokenClaims define the claims found in OIDC ID Tokens.
type IDTokenClaims struct {
	Nonce           string `json:"nonce,omitempty"`
	AuthTime        int64  `json:"auth_time,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`
	jwt.StandardClaims
	*ProfileClaims
	*EmailClaims
}

// Valid implements the jwt.Claims interface.
func (c IDTokenClaims) Valid() (err error) {
	return c.StandardClaims.Valid()
}

// ProfileClaims define the claims for the OIDC profile scope.
// https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
type ProfileClaims struct {
	Name string `json:"name,omitempty"`
}

// NewProfileClaims return a new ProfileClaims set from the provided
// jwt.Claims or nil.
func NewProfileClaims(claims jwt.Claims) *ProfileClaims {
	if claims == nil {
		return nil
	}

	return claims.(*ProfileClaims)
}

// Valid implements the jwt.Claims interface.
func (c ProfileClaims) Valid() error {
	return nil
}

// EmailClaims define the claims for the OIDC email scope.
// https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
type EmailClaims struct {
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
}

// NewEmailClaims return a new EmailClaims set from the provided
// jwt.Claims or nil.
func NewEmailClaims(claims jwt.Claims) *EmailClaims {
	if claims == nil {
		return nil
	}

	return claims.(*EmailClaims)
}

// Valid implements the jwt.Claims interface.
func (c EmailClaims) Valid() error {
	return nil
}

// UserInfoClaims define the claims defined by the OIDC UserInfo
// endpoint.
type UserInfoClaims struct {
	Subject string `json:"sub,omitempty"`
}

// Valid implements the jwt.Claims interface.
func (c UserInfoClaims) Valid() error {
	return nil
}

// RefreshTokenClaims define the claims used by refresh tokens.
type RefreshTokenClaims struct {
	IsRefreshToken     bool     `json:"kc.isRefreshToken"`
	ApprovedScopesList []string `json:"kc.approvedScopes"`
	Ref                string   `json:"kc.ref"`
	jwt.StandardClaims
}

// Valid implements the jwt.Claims interface.
func (c RefreshTokenClaims) Valid() error {
	if err := c.StandardClaims.Valid(); err != nil {
		return err
	}
	if c.IsRefreshToken {
		return nil
	}
	return errors.New("kc.isRefreshToken claim not valid")
}
