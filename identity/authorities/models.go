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
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"stash.kopano.io/kgol/oidc-go"
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

	Iss string `yaml:"iss"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`

	Insecure bool  `yaml:"insecure"`
	Default  bool  `yaml:"default"`
	Discover *bool `yaml:"discover"`

	Scopes              []string `yaml:"scopes"`
	ResponseType        string   `yaml:"response_type"`
	CodeChallengeMethod string   `yaml:"code_challenge_method"`

	RawMetadataEndpoint      string `yaml:"metadata_endpoint"`
	RawAuthorizationEndpoint string `yaml:"authorization_endpoint"`

	JWKS *jose.JSONWebKeySet `yaml:"jwks"`

	IdentityClaimName string `yaml:"identity_claim_name"`

	IdentityAliases       map[string]string `yaml:"identity_aliases,flow"`
	IdentityAliasRequired bool              `yaml:"identity_alias_required"`

	discover              bool     `yaml:"-"`
	metadataEndpoint      *url.URL `yaml:"-"`
	authorizationEndpoint *url.URL `yaml:"-"`

	validationKeys map[string]crypto.PublicKey

	mutex sync.RWMutex
	ready bool
}

// Validate validates the associated authority registration data and returns
// error if the data is not valid.
func (ar *AuthorityRegistration) Validate() error {
	if ar.RawMetadataEndpoint != "" {
		if u, err := url.Parse(ar.RawMetadataEndpoint); err == nil {
			ar.metadataEndpoint = u
		} else {
			return fmt.Errorf("invalid metadata_endpoint value: %v", err)
		}
	}
	if ar.RawAuthorizationEndpoint != "" {
		if u, err := url.Parse(ar.RawAuthorizationEndpoint); err == nil {
			if u.Scheme != "https" {
				return errors.New("authorization_endpoint must be https")
			}

			ar.authorizationEndpoint = u
		} else {
			return fmt.Errorf("invalid authorization_endpoint value: %v", err)
		}
	}
	if ar.JWKS != nil {
		if err := ar.setValidationKeysFromJWKS(ar.JWKS, false); err != nil {
			return err
		}
	}
	if ar.Discover != nil {
		ar.discover = *ar.Discover
	}

	switch ar.AuthorityType {
	case AuthorityTypeOIDC:
		// Additional behavior.
		if ar.metadataEndpoint == nil && (ar.Discover == nil || ar.discover == true) {
			if ar.Iss == "" {
				return fmt.Errorf("oidc authority iss is empty")
			}
			if metadataEndpoint, mdeErr := url.Parse(ar.Iss); mdeErr == nil {
				metadataEndpoint.Path = "/.well-known/openid-configuration"
				ar.metadataEndpoint = metadataEndpoint
				ar.discover = true
			} else {
				return fmt.Errorf("invalid iss value: %v", mdeErr)
			}
		}

		if !ar.discover {
			if ar.authorizationEndpoint == nil {
				return errors.New("authorization_endpoint is empty")
			}
			if ar.JWKS == nil && !ar.Insecure {
				return errors.New("jwks is empty")
			}
		}
	}

	return nil
}

func (ar *AuthorityRegistration) setValidationKeysFromJWKS(jwks *jose.JSONWebKeySet, skipInvalid bool) error {
	if jwks == nil || len(jwks.Keys) == 0 {
		ar.validationKeys = nil
		return nil
	}

	ar.validationKeys = make(map[string]crypto.PublicKey)
	skipped := 0
	for _, jwk := range jwks.Keys {
		if jwk.Use == "sig" {
			if key, ok := jwk.Key.(crypto.PublicKey); ok {
				ar.validationKeys[jwk.KeyID] = key
			} else {
				if !skipInvalid {
					return fmt.Errorf("failed to decode public key")
				} else {
					skipped++
				}
			}
		}
	}
	if skipped > 0 {
		return fmt.Errorf("failed to decode %d keys in set", skipped)
	}

	return nil
}

// Initialize initializes the associated registration with the provided context.
func (ar *AuthorityRegistration) Initialize(ctx context.Context, logger logrus.FieldLogger) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	switch ar.AuthorityType {
	case AuthorityTypeOIDC:
		if ar.authorizationEndpoint != nil && ar.validationKeys != nil {
			ar.ready = true
		}
		if ar.metadataEndpoint == nil {
			return fmt.Errorf("no metadata_endpoint set")
		}

		return initializeOIDC(ctx, logger, ar)
	}

	return nil
}
