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

	"github.com/mendsley/gojwk"
	_ "gopkg.in/yaml.v2" // Make sure we have yaml.
)

// RegistryData is the base structur of our client registry configuration file.
type RegistryData struct {
	Clients []*ClientRegistration `yaml:"clients,flow"`
}

// ClientRegistration defines a client with its properties.
type ClientRegistration struct {
	ID              string `yaml:"id"`
	Secret          string `yaml:"secret"`
	Name            string `yaml:"name"`
	ApplicationType string `yaml:"application_type"`

	Trusted       bool     `yaml:"trusted"`
	TrustedScopes []string `yaml:"trusted_scopes"`
	Insecure      bool     `yaml:"insecure"`

	RedirectURIs []string `yaml:"redirect_uris,flow"`
	Origins      []string `yaml:"origins,flow"`

	JWKS                       *gojwk.Key `yaml:"jwks"`
	RawRequestObjectSigningAlg string     `yaml:"request_object_signing_alg"`
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
	}, nil
}
