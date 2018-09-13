/*
 * Copyright 2018 Kopano and its licensors
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
	"fmt"

	"github.com/dgrijalva/jwt-go"

	"stash.kopano.io/kc/konnect/oidc"
)

// AuthorizeScopes uses the provided manager and user to filter the provided
// scopes and returns a mapping of only the authorized scopes.
func AuthorizeScopes(manager Manager, user User, scopes map[string]bool) (map[string]bool, map[string]bool) {
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

// GetUserClaimsForScopes returns a mapping of user claims of the provided user
// filtered by the provided scopes.
func GetUserClaimsForScopes(user User, scopes map[string]bool) map[string]jwt.Claims {
	if user == nil {
		return nil
	}

	claims := make(map[string]jwt.Claims)

	if authorizedScope, _ := scopes[oidc.ScopeEmail]; authorizedScope {
		if userWithEmail, ok := user.(UserWithEmail); ok {
			claims[oidc.ScopeEmail] = &oidc.EmailClaims{
				Email:         userWithEmail.Email(),
				EmailVerified: userWithEmail.EmailVerified(),
			}
		}
	}
	if authorizedScope, _ := scopes[oidc.ScopeProfile]; authorizedScope {
		if userWithProfile, ok := user.(UserWithProfile); ok {
			claims[oidc.ScopeProfile] = &oidc.ProfileClaims{
				Name:       userWithProfile.Name(),
				FamilyName: userWithProfile.FamilyName(),
				GivenName:  userWithProfile.GivenName(),
			}
		}
	}

	if userWithScopedClaims, ok := user.(UserWithScopedClaims); ok {
		// Inject additional scope claims.
		claims[""] = userWithScopedClaims.ScopedClaims(scopes)
	}

	return claims
}

// GetSessionRef builds a per useser and audience unique identifier.
func GetSessionRef(label string, audience string, userID string) *string {
	if userID == "" {
		return nil
	}

	// NOTE(longsleep): For now we ignore the audience. Seems not to have any
	// use to keep multiple sessions from Konnect per audience.
	sessionRef := fmt.Sprintf("%s:-:%s", label, userID)
	return &sessionRef
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
