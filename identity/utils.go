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
	"stash.kopano.io/kc/konnect/oidc/payload"
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
	for _, scope := range manager.ScopesSupported(scopes) {
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
func GetUserClaimsForScopes(user User, scopes map[string]bool, requestedClaimsMaps []*payload.ClaimsRequestMap) map[string]jwt.Claims {
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

	// Add additional supported values for email and profile claims.
	unknownRequestedClaimsWithValue := make(map[string]interface{})
	for _, requestedClaimMap := range requestedClaimsMaps {
		for requestedClaim, requestedClaimEntry := range *requestedClaimMap {
			// NOTE(longsleep): We ignore the actuall value of the claim request
			// and always return requested scopes with standard behavior.
			if scope, ok := payload.GetScopeForClaim(requestedClaim); ok {
				if authorizedScope, _ := scopes[scope]; !authorizedScope {
					// Add claim values if known.
					switch scope {
					case oidc.ScopeEmail:
						if userWithEmail, ok := user.(UserWithEmail); ok {
							scopeClaims := oidc.NewEmailClaims(claims[scope])
							if scopeClaims == nil {
								scopeClaims = &oidc.EmailClaims{}
								claims[scope] = scopeClaims
							}
							switch requestedClaim {
							case oidc.EmailClaim:
								scopeClaims.Email = userWithEmail.Email()
								fallthrough // Always include EmailVerified claim.
							case oidc.EmailVerifiedClaim:
								scopeClaims.EmailVerified = userWithEmail.EmailVerified()
							}
						}
					case oidc.ScopeProfile:
						if userWithProfile, ok := user.(UserWithProfile); ok {
							scopeClaims := oidc.NewProfileClaims(claims[scope])
							if scopeClaims == nil {
								scopeClaims = &oidc.ProfileClaims{}
								claims[scope] = scopeClaims
							}
							switch requestedClaim {
							case oidc.NameClaim:
								scopeClaims.Name = userWithProfile.Name()
							case oidc.FamilyNameClaim:
								scopeClaims.Name = userWithProfile.FamilyName()
							case oidc.GivenNameClaim:
								scopeClaims.Name = userWithProfile.GivenName()
							}
						}
					}
				}
			} else {
				// Add claims which are unknown here to a list of unknown claims
				// with value if the requested claim is with value. This returns
				// the requested claim as is with the provided value.
				if requestedClaimEntry != nil && requestedClaimEntry.Value != nil {
					unknownRequestedClaimsWithValue[requestedClaim] = requestedClaimEntry.Value
				}
			}
		}
	}

	// Add extra claims. Those can  either come from the backend user if it
	// has own scoped claims or might be defined as value by the request.
	var claimsWithoutScope jwt.MapClaims
	if userWithScopedClaims, ok := user.(UserWithScopedClaims); ok {
		// Inject additional scope claims.
		claimsWithoutScope = userWithScopedClaims.ScopedClaims(scopes)
	}
	if len(unknownRequestedClaimsWithValue) > 0 {
		if claimsWithoutScope == nil {
			claimsWithoutScope = make(jwt.MapClaims)
		}
		for claim, value := range unknownRequestedClaimsWithValue {
			claimsWithoutScope[claim] = value
		}
	}
	if claimsWithoutScope != nil {
		claims[""] = claimsWithoutScope
	}

	return claims
}

// GetSessionRef builds a per user and audience unique identifier.
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
