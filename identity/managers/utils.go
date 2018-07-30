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

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
)

func setupSupportedScopes(scopes []string, extra []string, override []string) []string {
	if len(override) > 0 {
		return override
	}

	return append(scopes, extra...)
}

func isKnownScope(scope string) bool {
	// Only authorize the scopes we know.
	switch scope {
	case oidc.ScopeOpenID:
	default:
		// Unknown scopes end up here and are not getting authorized.
		return false
	}

	return true
}

func authorizeScopes(manager identity.Manager, user identity.User, scopes map[string]bool) (map[string]bool, map[string]bool) {
	if user == nil {
		return nil, nil
	}

	authorizedScopes := make(map[string]bool)
	unauthorizedScopes := make(map[string]bool)
	supportedScopes := make(map[string]bool)
	for _, scope := range manager.ScopesSupported() {
		supportedScopes[scope] = true
	}

	for scope, authorizedScope := range scopes {
		for {
			if !authorizedScope {
				// Incoming not authorized.
				break
			}

			authorizedScope = isKnownScope(scope)

			if !authorizedScope {
				if _, ok := supportedScopes[scope]; ok {
					authorizedScope = true
				}
			}

			break
		}

		if authorizedScope {
			authorizedScopes[scope] = true
		} else {
			unauthorizedScopes[scope] = false
		}
	}

	return authorizedScopes, unauthorizedScopes
}

func getUserClaimsForScopes(user identity.User, scopes map[string]bool) map[string]jwt.Claims {
	if user == nil {
		return nil
	}

	claims := make(map[string]jwt.Claims)

	if authorizedScope, _ := scopes[oidc.ScopeEmail]; authorizedScope {
		if userWithEmail, ok := user.(identity.UserWithEmail); ok {
			claims[oidc.ScopeEmail] = &oidc.EmailClaims{
				Email:         userWithEmail.Email(),
				EmailVerified: userWithEmail.EmailVerified(),
			}
		}
	}
	if authorizedScope, _ := scopes[oidc.ScopeProfile]; authorizedScope {
		if userWithProfile, ok := user.(identity.UserWithProfile); ok {
			claims[oidc.ScopeProfile] = &oidc.ProfileClaims{
				Name:       userWithProfile.Name(),
				FamilyName: userWithProfile.FamilyName(),
				GivenName:  userWithProfile.GivenName(),
			}
		}
	}

	if userWithScopedClaims, ok := user.(identity.UserWithScopedClaims); ok {
		// Inject additional scope claims.
		claims[""] = userWithScopedClaims.ScopedClaims(scopes)
	}

	return claims
}
