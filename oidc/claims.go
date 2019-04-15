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
	"github.com/dgrijalva/jwt-go"
)

// IDTokenClaims define the claims found in OIDC ID Tokens.
type IDTokenClaims struct {
	jwt.StandardClaims

	Nonce           string `json:"nonce,omitempty"`
	AuthTime        int64  `json:"auth_time,omitempty"`
	AccessTokenHash string `json:"at_hash,omitempty"`
	CodeHash        string `json:"c_hash,omitempty"`

	*ProfileClaims
	*EmailClaims

	*SessionClaims
}

// Valid implements the jwt.Claims interface.
func (c IDTokenClaims) Valid() (err error) {
	return c.StandardClaims.Valid()
}

// ProfileClaims define the claims for the OIDC profile scope.
// https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
type ProfileClaims struct {
	Name              string `json:"name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
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

// SessionClaims define claims related to front end sessions, for example as
// specified by https://openid.net/specs/openid-connect-frontchannel-1_0.html
type SessionClaims struct {
	SessionID string `json:"sid,omitempty"`
}
