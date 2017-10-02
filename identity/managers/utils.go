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
	"github.com/dgrijalva/jwt-go"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
)

func authorizeScopes(user identity.User, scopes map[string]bool) (map[string]bool, map[string]jwt.Claims) {
	authorizedScopes := make(map[string]bool)
	claims := make(map[string]jwt.Claims)
	for scope, authorizedScope := range scopes {
		if !authorizedScope {
			continue
		}
		switch scope {
		case oidc.ScopeOpenID:
			// breaks
		case oidc.ScopeEmail:
			if userWithEmail, ok := user.(identity.UserWithEmail); ok {
				claims[oidc.ScopeEmail] = &oidc.EmailClaims{
					Email:         userWithEmail.Email(),
					EmailVerified: userWithEmail.EmailVerified(),
				}
			}
		case oidc.ScopeProfile:
			if userWithProfile, ok := user.(identity.UserWithProfile); ok {
				claims[oidc.ScopeProfile] = &oidc.ProfileClaims{
					Name: userWithProfile.Name(),
				}
			}
		case konnect.ScopeID:
			// breaks
		default:
			authorizedScope = false
		}
		if authorizedScope {
			authorizedScopes[scope] = true
		}
	}

	return authorizedScopes, claims
}
