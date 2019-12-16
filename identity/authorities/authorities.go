/*
 * Copyright 2017-2019 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

// IsReady returns wether or not the associated registration entry was ready
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
