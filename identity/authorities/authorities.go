/*
 * Copyright 2019 Kopano and its licensors
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

package authorities

import (
	"crypto"
	"errors"
	"fmt"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"stash.kopano.io/kgol/oidc-go"
)

// Details hold detail information about authorities identified by ID.
type Details struct {
	ID            string
	Name          string
	AuthorityType string

	ClientID     string
	ClientSecret string

	Insecure bool

	Scopes              []string
	ResponseType        string
	CodeChallengeMethod string

	Registration *AuthorityRegistration

	ready bool

	AuthorizationEndpoint *url.URL

	validationKeys map[string]crypto.PublicKey
}

// IsReady returns wether or not the assosiated registration entry was ready
// at time of creation of the associated details.
func (d *Details) IsReady() bool {
	return d.ready
}

// IdentityClaimValue returns the claim value of the provided claims from the
// claim defined at the associated registration.
func (d *Details) IdentityClaimValue(claims map[string]interface{}) (string, error) {
	icn := d.Registration.IdentityClaimName
	if icn == "" {
		icn = oidc.PreferredUsernameClaim
	}

	cvr, ok := claims[icn]
	if !ok {
		return "", errors.New("identity claim not found")
	}
	cvs, ok := cvr.(string)
	if !ok {
		return "", errors.New("identify claim has invalid type")
	}

	// Convert claim value.
	whitelisted := false
	if d.Registration.IdentityAliases != nil {
		if alias, ok := d.Registration.IdentityAliases[cvs]; ok && alias != "" {
			cvs = alias
			whitelisted = true
		}
	}

	// Check whitelist.
	if d.Registration.IdentityAliasRequired && !whitelisted {
		return "", errors.New("identity claim has no alias")
	}

	return cvs, nil
}

// Keyfunc returns a key func to validate JWTs with the keys of the associated
// authority registration.
func (d *Details) Keyfunc() jwt.Keyfunc {
	return d.validateJWT
}

func (d *Details) validateJWT(token *jwt.Token) (interface{}, error) {
	rawAlg, ok := token.Header[oidc.JWTHeaderAlg]
	if !ok {
		return nil, errors.New("No alg header")
	}
	alg, ok := rawAlg.(string)
	if !ok {
		return nil, errors.New("Invalid alg value")
	}
	switch jwt.GetSigningMethod(alg).(type) {
	case *jwt.SigningMethodRSA:
	case *jwt.SigningMethodECDSA:
	case *jwt.SigningMethodRSAPSS:
	default:
		return nil, fmt.Errorf("Unexpected alg value")
	}
	rawKid, ok := token.Header[oidc.JWTHeaderKeyID]
	if !ok {
		return nil, fmt.Errorf("No kid header")
	}
	kid, ok := rawKid.(string)
	if !ok {
		return nil, fmt.Errorf("Invalid kid value")
	}

	if key, ok := d.validationKeys[kid]; ok {
		return key, nil
	}

	return nil, errors.New("No key available")
}
