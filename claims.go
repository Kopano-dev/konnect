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

package konnect

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

// Access token claims used by Konnect.
const (
	IsAccessTokenClaim    = "kc.isAccessToken"
	AuthorizedScopesClaim = "kc.authorizedScopes"
	IsRefreshTokenClaim   = "kc.isRefreshToken"
	RefClaim              = "kc.ref"
	IdentityClaim         = "kc.identity"
)

// Identifier claims used by Konnect.
const (
	IdentifiedUsernameClaim    = "kc.i.un"
	IdentifiedDisplayNameClaim = "kc.i.dn"
)

// AccessTokenClaims define the claims found in access tokens issued
// by Konnect.
type AccessTokenClaims struct {
	IsAccessToken        bool     `json:"kc.isAccessToken"`
	AuthorizedScopesList []string `json:"kc.authorizedScopes"`
	jwt.StandardClaims
	IdentityClaims jwt.MapClaims `json:"kc.identity"`
}

// Valid implements the jwt.Claims interface.
func (c AccessTokenClaims) Valid() error {
	if err := c.StandardClaims.Valid(); err != nil {
		return err
	}
	if c.IdentityClaims != nil {
		if err := c.IdentityClaims.Valid(); err != nil {
			return err
		}
	}
	if c.IsAccessToken {
		return nil
	}
	return errors.New("kc.isAccessToken claim not valid")
}

// AuthorizedScopes returns a map with scope keys and true value of all scopes
// set in the accociated access token.
func (c AccessTokenClaims) AuthorizedScopes() map[string]bool {
	authorizedScopes := make(map[string]bool)
	for _, scope := range c.AuthorizedScopesList {
		authorizedScopes[scope] = true
	}

	return authorizedScopes
}

// RefreshTokenClaims define the claims used by refresh tokens.
type RefreshTokenClaims struct {
	IsRefreshToken     bool     `json:"kc.isRefreshToken"`
	ApprovedScopesList []string `json:"kc.approvedScopes"`
	Ref                string   `json:"kc.ref"`
	jwt.StandardClaims
	IdentityClaims jwt.MapClaims `json:"kc.identity"`
}

// Valid implements the jwt.Claims interface.
func (c RefreshTokenClaims) Valid() error {
	if err := c.StandardClaims.Valid(); err != nil {
		return err
	}
	if c.IdentityClaims != nil {
		if err := c.IdentityClaims.Valid(); err != nil {
			return err
		}
	}
	if c.IsRefreshToken {
		return nil
	}
	return errors.New("kc.isRefreshToken claim not valid")
}

// IDClaims define the claims used with the konnect/id scope.
type IDClaims struct {
	// NOTE(longsleep): Always keep these claims compatible with the GitLab API
	// https://docs.gitlab.com/ce/api/users.html#for-user.
	KCID         int64  `json:"id,omitempty"`
	KCIDUsername string `json:"username,omitempty"`
}

// Valid implements the jwt.Claims interface.
func (c IDClaims) Valid() error {
	if c.KCIDUsername == "" {
		return errors.New("username claim not valid")
	}
	return nil
}

// UniqueUserIDClaims define the claims used with the konnect/uuid scope.
type UniqueUserIDClaims struct {
	KCUniqueUserID string `json:"kc.uuid,omitempty"`
}

// Valid implements the jwt.Claims interface.
func (c UniqueUserIDClaims) Valid() error {
	if c.KCUniqueUserID == "" {
		return errors.New("kc.uuid claim not valid")
	}
	return nil
}
