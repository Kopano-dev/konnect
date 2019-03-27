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
	"github.com/mendsley/gojwk"

	"stash.kopano.io/kc/konnect/oidc"
)

// Supported Authority kind string values.
const (
	AuthorityTypeOIDC = "oidc"
)

// Authority default values.
var (
	authorityDefaultScopes              = []string{oidc.ScopeOpenID, oidc.ScopeProfile}
	authorityDefaultResponseType        = oidc.ResponseTypeIDToken
	authorityDefaultCodeChallengeMethod = oidc.S256CodeChallengeMethod
	authorityDefaultIdentityClaimName   = oidc.PreferredUsernameClaim
)

// RegistryData is the base structure of our authority registration configuration file.
type RegistryData struct {
	Authorities []*AuthorityRegistration `yaml:"authorities,flow"`
}

// AuthorityRegistration defines an authority with its properties.
type AuthorityRegistration struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	AuthorityType string `yaml:"authority_type"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	Insecure bool `yaml:"insecure"`
	Default  bool `yaml:"default"`

	Scopes              []string `yaml:"scopes"`
	ResponseType        string   `yaml:"response_type"`
	CodeChallengeMethod string   `yaml:"code_challenge_method"`

	RawAuthorizationEndpoint string `yaml:"authorization_endpoint"`

	JWKS *gojwk.Key `yaml:"jwks"`

	IdentityClaimName string `yaml:"identity_claim_name"`

	IdentityAliases       map[string]string `yaml:"identity_aliases,flow"`
	IdentityAliasRequired bool              `yaml:"identity_alias_required"`

	AuthorizationEndpoint *url.URL `yaml:"-"`

	validationKeys map[string]crypto.PublicKey
}

// Validate validates the associated authority registration data and returns
// error if the data is not valid.
func (ar *AuthorityRegistration) Validate() error {
	if ar.RawAuthorizationEndpoint != "" {
		if u, err := url.Parse(ar.RawAuthorizationEndpoint); err == nil {
			if u.Scheme != "https" {
				return errors.New("authorization_endpoint must be https")
			}

			ar.AuthorizationEndpoint = u
		} else {
			return fmt.Errorf("invalid authorization_endpoint value: %v", err)
		}
	}
	if ar.JWKS != nil {
		ar.validationKeys = make(map[string]crypto.PublicKey)
		for _, jwk := range ar.JWKS.Keys {
			if jwk.Use == "sig" {
				if key, err := jwk.DecodePublicKey(); err == nil {
					ar.validationKeys[jwk.Kid] = key
				} else {
					return fmt.Errorf("failed to decode public key: %v", err)
				}
			}
		}
	}

	return nil
}

// IdentityClaimValue returns the claim value of the provided claims from the
// claim defined at the associated registration.
func (ar *AuthorityRegistration) IdentityClaimValue(claims map[string]interface{}) (string, error) {
	icn := ar.IdentityClaimName
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
	if ar.IdentityAliases != nil {
		if alias, ok := ar.IdentityAliases[cvs]; ok && alias != "" {
			cvs = alias
			whitelisted = true
		}
	}

	// Check whitelist.
	if ar.IdentityAliasRequired && !whitelisted {
		return "", errors.New("identity claim has no alias")
	}

	return cvs, nil
}

// Keyfunc returns a key func to validate JWTs with the keys of the associated
// authority registration.
func (ar *AuthorityRegistration) Keyfunc() jwt.Keyfunc {
	return ar.validateJWT
}

func (ar *AuthorityRegistration) validateJWT(token *jwt.Token) (interface{}, error) {
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
	if key, ok := ar.validationKeys[kid]; ok {
		return key, nil
	}

	return nil, errors.New("No key available")
}
