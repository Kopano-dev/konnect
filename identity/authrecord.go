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

package identity

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type authRecord struct {
	manager Manager

	sub              string
	authorizedScopes map[string]bool
	claimsByScope    map[string]jwt.Claims

	user     PublicUser
	authTime time.Time
}

// NewAuthRecord returns a implementation of identity.AuthRecord holding
// the provided data in memory.
func NewAuthRecord(manager Manager, sub string, authorizedScopes map[string]bool, claimsByScope map[string]jwt.Claims) AuthRecord {
	if authorizedScopes == nil {
		authorizedScopes = make(map[string]bool)
	}

	return &authRecord{
		manager: manager,

		sub:              sub,
		authorizedScopes: authorizedScopes,
		claimsByScope:    claimsByScope,
	}
}

// Subject implements the identity.AuthRecord  interface.
func (r *authRecord) Subject() string {
	return r.sub
}

// AuthorizedScopes implements the identity.AuthRecord  interface.
func (r *authRecord) AuthorizedScopes() map[string]bool {
	return r.authorizedScopes
}

// AuthorizeScopes implements the identity.AuthRecord  interface.
func (r *authRecord) AuthorizeScopes(scopes map[string]bool) {
	authorizedScopes, unauthorizedScopes := AuthorizeScopes(r.manager, r.User(), scopes)

	for scope, grant := range authorizedScopes {
		if grant {
			r.authorizedScopes[scope] = grant
		} else {
			delete(r.authorizedScopes, scope)
		}
	}
	for scope := range unauthorizedScopes {
		delete(r.authorizedScopes, scope)
	}
}

// Claims implements the identity.AuthRecord  interface.
func (r *authRecord) Claims(scopes ...string) []jwt.Claims {
	result := make([]jwt.Claims, len(scopes))
	for idx, scope := range scopes {
		if claimsForScope, ok := r.claimsByScope[scope]; ok {
			result[idx] = claimsForScope
		}
	}

	return result
}

// User implements the identity.AuthRecord interface.
func (r *authRecord) User() PublicUser {
	return r.user
}

// SetUser implements the identity.AuthRecord interface.
func (r *authRecord) SetUser(u PublicUser) {
	r.user = u
}

// LoggedOn implements the identity.AuthRecord interface
func (r *authRecord) LoggedOn() (bool, time.Time) {
	return !r.authTime.IsZero(), r.authTime
}

// SetAuthTime implements the identity.AuthRecord interface.
func (r *authRecord) SetAuthTime(authTime time.Time) {
	r.authTime = authTime
}
