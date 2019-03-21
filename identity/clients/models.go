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

package clients

import (
	"crypto"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/mendsley/gojwk"
	_ "gopkg.in/yaml.v2" // Make sure we have yaml.
	"stash.kopano.io/kgol/rndm"
)

// RegistryData is the base structur of our client registry configuration file.
type RegistryData struct {
	Clients []*ClientRegistration `yaml:"clients,flow"`
}

// ClientRegistration defines a client with its properties.
type ClientRegistration struct {
	ID     string `yaml:"id" json:"-"`
	Secret string `yaml:"secret" json:"-"`

	Trusted       bool     `yaml:"trusted" json:"-"`
	TrustedScopes []string `yaml:"trusted_scopes" json:"-"`
	Insecure      bool     `yaml:"insecure" json:"-"`

	Dynamic         bool  `yaml:"-" json:"-"`
	IDIssuedAt      int64 `yaml:"-" json:"-"`
	SecretExpiresAt int64 `yaml:"-" json:"-"`

	Contacts        []string `yaml:"contacts,flow" json:"contacts,omitempty"`
	Name            string   `yaml:"name" json:"name,omitempty"`
	URI             string   `yaml:"uri"  json:"uri,omitempty"`
	GrantTypes      []string `yaml:"grant_types,flow" json:"grant_types,omitempty"`
	ApplicationType string   `yaml:"application_type"  json:"application_type,omitempty"`

	RedirectURIs []string `yaml:"redirect_uris,flow" json:"redirect_uris,omitempty"`
	Origins      []string `yaml:"origins,flow" json:"-"`

	JWKS *gojwk.Key `yaml:"jwks" json:"-"`

	RawIDTokenSignedResponseAlg    string `yaml:"id_token_signed_response_alg" json:"id_token_signed_response_alg,omitempty"`
	RawUserInfoSignedResponseAlg   string `yaml:"userinfo_signed_response_alg" json:"userinfo_signed_response_alg,omitempty"`
	RawRequestObjectSigningAlg     string `yaml:"request_object_signing_alg" json:"request_object_signing_alg,omitempty"`
	RawTokenEndpointAuthMethod     string `yaml:"token_endpoint_auth_method" json:"token_endpoint_auth_method,omitempty"`
	RawTokenEndpointAuthSigningAlg string `yaml:"token_endpoint_auth_signing_alg"  json:"token_endpoint_auth_signing_alg,omitempty"`

	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris,flow" json:"post_logout_redirect_uris,omitempty"`
}

// Secure looks up the a matching key from the accociated client registration
// and returns its public key part as a secured client.
func (cr *ClientRegistration) Secure(rawKid interface{}) (*Secured, error) {
	var kid string
	var key crypto.PublicKey
	var err error

	switch len(cr.JWKS.Keys) {
	case 0:
		// breaks
	case 1:
		// Use the one and only, no matter what kid says.
		key, err = cr.JWKS.Keys[0].DecodePublicKey()
		if err != nil {
			return nil, err
		}
		kid = cr.JWKS.Keys[0].Kid
	default:
		// Find by kid.
		kid, _ = rawKid.(string)
		if kid == "" {
			kid = "default"
		}
		for _, k := range cr.JWKS.Keys {
			if kid == k.Kid {
				key, err = k.DecodePublicKey()
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}

	if key == nil {
		return nil, fmt.Errorf("unknown kid")
	}

	return &Secured{
		ID:              cr.ID,
		DisplayName:     cr.Name,
		ApplicationType: cr.ApplicationType,

		Kid:       kid,
		PublicKey: key,

		TrustedScopes: cr.TrustedScopes,

		Registration: cr,
	}, nil
}

// SetDynamic modifieds the required data for the associated client registration
// so it becomes a dynamic client.
func (cr *ClientRegistration) SetDynamic() error {
	if cr.ID != "" {
		return fmt.Errorf("has ID already")
	}

	cr.IDIssuedAt = time.Now().Unix()
	cr.SecretExpiresAt = time.Now().Add(24 * time.Hour).Unix()
	cr.Dynamic = true

	// Create random secret.
	// TODO(longsleep): Encrypt sub with iss specific key.
	sub := rndm.GenerateRandomString(32)

	// Stateless Dynamic Client Registration encodes all relevant data in the
	// client_id. See https://openid.net/specs/openid-connect-registration-1_0.html#StatelessRegistration
	// for more information. We use a JWT as client_id.
	claims := &RegistrationClaims{
		StandardClaims: jwt.StandardClaims{
			Subject:   sub,
			IssuedAt:  cr.IDIssuedAt,
			ExpiresAt: cr.SecretExpiresAt,
		},
		ClientRegistration: cr,
	}
	// TODO(longsleep): Use signed JWT.
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	id, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return fmt.Errorf("failed to sign token for dynamic client_id: %v", err)
	}

	cr.ID = id
	cr.Secret = sub

	return nil
}
