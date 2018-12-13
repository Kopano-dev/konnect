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

package payload

import (
	"stash.kopano.io/kc/konnect/oidc"
)

var scopedClaims = map[string]string{
	oidc.NameClaim:              oidc.ScopeProfile,
	oidc.FamilyNameClaim:        oidc.ScopeProfile,
	oidc.GivenNameClaim:         oidc.ScopeProfile,
	oidc.MiddleNameClaim:        oidc.ScopeProfile,
	oidc.PreferredUsernameClaim: oidc.ScopeProfile,
	oidc.ProfileClaim:           oidc.ScopeProfile,
	oidc.PictureClaim:           oidc.ScopeProfile,
	oidc.WebsiteClaim:           oidc.ScopeProfile,
	oidc.GenderClaim:            oidc.ScopeProfile,
	oidc.BirthdateClaim:         oidc.ScopeProfile,
	oidc.ZoneinfoClaim:          oidc.ScopeProfile,
	oidc.UpdatedAtClaim:         oidc.ScopeProfile,

	oidc.EmailClaim:         oidc.ScopeEmail,
	oidc.EmailVerifiedClaim: oidc.ScopeEmail,
}

// ClaimsRequest define the base claims structure for OpenID Connect claims
// request parameter value as specified at
// https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
type ClaimsRequest struct {
	UserInfo *ClaimsRequestMap `json:"userinfo,omitempty"`
	IDToken  *ClaimsRequestMap `json:"id_token,omitempty"`
}

// ApplyScopes removes all claims requests from the accociated claims request
// which are not mapped to one of the provided approved scopes.
func (cr *ClaimsRequest) ApplyScopes(approvedScopes map[string]bool) error {
	if cr.UserInfo != nil {
		for claim := range *cr.UserInfo {
			if approved := approvedScopes[scopedClaims[claim]]; !approved {
				delete(*cr.UserInfo, claim)
			}
		}
	}
	if cr.IDToken != nil {
		for claim := range *cr.IDToken {
			if approved := approvedScopes[scopedClaims[claim]]; !approved {
				delete(*cr.IDToken, claim)
			}
		}
	}

	return nil
}

// Scopes adds all scopes of the accociated claims requests claims to
// the provied scopes mapping safe the scopes already defined in the provided
// excluded scopes mapping.
func (cr *ClaimsRequest) Scopes(excludedScopes map[string]bool) []string {
	scopesMap := make(map[string]bool)

	if cr.UserInfo != nil {
		for claim := range *cr.UserInfo {
			scope := scopedClaims[claim]
			if _, excluded := excludedScopes[scope]; !excluded {
				scopesMap[scope] = true
			}
		}
	}
	if cr.IDToken != nil {
		for claim := range *cr.IDToken {
			scope := scopedClaims[claim]
			if _, excluded := excludedScopes[scope]; !excluded {
				scopesMap[scope] = true
			}
		}
	}

	scopes := make([]string, 0)
	for scope := range scopesMap {
		scopes = append(scopes, scope)
	}

	return scopes
}

// ClaimsRequestMap defines a mapping of claims request values used with
// OpenID Connect claims request parameter values.
type ClaimsRequestMap map[string]*ClaimsRequestValue

// ClaimsRequestValue is the claims request detail definition of an OpenID
// Connect claims request parameter value.
type ClaimsRequestValue struct {
	Essential bool          `json:"essential,omitempty"`
	Value     interface{}   `json:"value,omitempty"`
	Values    []interface{} `json:"values,omitempty"`
}
