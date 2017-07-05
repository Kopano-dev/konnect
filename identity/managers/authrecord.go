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
	"stash.kopano.io/kc/konnect/identity"

	"github.com/dgrijalva/jwt-go"
)

type authRecord struct {
	userid           string
	authorizedScopes map[string]bool
	claims           map[string]jwt.Claims
}

// NewAuthRecord returns a implementation of identity.AuthRecord holding
// the provided data in memory.
func NewAuthRecord(userid string, authorizedScopes map[string]bool, claims map[string]jwt.Claims) identity.AuthRecord {
	if authorizedScopes == nil {
		authorizedScopes = make(map[string]bool)
	}

	return &authRecord{
		userid:           userid,
		authorizedScopes: authorizedScopes,
		claims:           claims,
	}
}

// UserID implements the identity.AuthRecord  interface.
func (r *authRecord) UserID() string {
	return r.userid
}

// AuthorizedScopes implements the identity.AuthRecord  interface.
func (r *authRecord) AuthorizedScopes() map[string]bool {
	return r.authorizedScopes
}

// AuthorizeScopes implements the identity.AuthRecord  interface.
func (r *authRecord) AuthorizeScopes(scopes map[string]bool) {
	for scope, grant := range scopes {
		if grant {
			r.authorizedScopes[scope] = grant
		} else {
			delete(r.authorizedScopes, scope)
		}
	}
}

// Claims implements the identity.AuthRecord  interface.
func (r *authRecord) Claims(scopes ...string) []jwt.Claims {
	result := make([]jwt.Claims, len(scopes))
	for idx, scope := range scopes {
		if claims, ok := r.claims[scope]; ok {
			result[idx] = claims
		}
	}

	return result
}
