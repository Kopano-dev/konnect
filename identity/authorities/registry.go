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
	"errors"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// Registry implements the registry for registered authorities.
type Registry struct {
	mutex sync.RWMutex

	defaultID   string
	authorities map[string]*AuthorityRegistration

	logger logrus.FieldLogger
}

// NewRegistry creates a new authorizations Registry with the provided parameters.
func NewRegistry(registrationConfFilepath string, logger logrus.FieldLogger) (*Registry, error) {
	registryData := &RegistryData{}

	if registrationConfFilepath != "" {
		logger.Debugf("parsing authorities registration conf from %v", registrationConfFilepath)
		registryFile, err := ioutil.ReadFile(registrationConfFilepath)
		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(registryFile, registryData)
		if err != nil {
			return nil, err
		}
	}

	r := &Registry{
		authorities: make(map[string]*AuthorityRegistration),

		logger: logger,
	}

	var defaultAuthority *AuthorityRegistration
	for _, authority := range registryData.Authorities {
		validateErr := authority.Validate()
		registerErr := r.Register(authority)
		fields := logrus.Fields{
			"id":                 authority.ID,
			"client_id":          authority.ClientID,
			"with_client_secret": authority.ClientSecret != "",
			"authority_type":     authority.AuthorityType,
			"insecure":           authority.Insecure,
			"default":            authority.Default,
			"alias_required":     authority.IdentityAliasRequired,
		}

		if validateErr != nil {
			logger.WithError(validateErr).WithFields(fields).Warnln("skipped registration of invalid authority entry")
			continue
		}
		if registerErr != nil {
			logger.WithError(registerErr).WithFields(fields).Warnln("skipped registration of invalid authority")
			continue
		}
		if authority.Default || defaultAuthority == nil {
			if defaultAuthority == nil || !defaultAuthority.Default {
				defaultAuthority = authority
			} else {
				logger.Warnln("ignored default authority flag since already have a default")
			}
		} else {
			// TODO(longsleep): Implement authority selection.
			logger.Warnln("non-default additional authorities are not supported yet")
		}

		logger.WithFields(fields).Debugln("registered authority")
	}

	if defaultAuthority != nil {
		if defaultAuthority.Default {
			r.defaultID = defaultAuthority.ID
			logger.WithField("id", defaultAuthority.ID).Infoln("using external default authority")
		} else {
			logger.Warnln("non-default authorities are not supported yet")
		}
	}

	return r, nil
}

// Register validates the provided authority registration and adds the authority
// to the accociated registry if valid. Returns error otherwise.
func (r *Registry) Register(authority *AuthorityRegistration) error {
	if authority.ID == "" {
		if authority.Name != "" {
			authority.ID = authority.Name
			r.logger.WithField("id", authority.ID).Warnln("authority has no id, using name")
		} else {
			return errors.New("no authority id")
		}
	}
	if authority.ClientID == "" {
		return errors.New("invalid authority client_id")
	}

	switch authority.AuthorityType {
	case AuthorityTypeOIDC:
		// Validate mandatory fields.
		if authority.AuthorizationEndpoint == nil {
			return errors.New("authorization_endpoint is empty")
		}
		if authority.JWKS == nil && !authority.Insecure {
			return errors.New("jwks is empty")
		}

		// Ensure some defaults.
		if len(authority.Scopes) == 0 {
			authority.Scopes = authorityDefaultScopes
		}
		if authority.ResponseType == "" {
			authority.ResponseType = authorityDefaultResponseType
		}
		if authority.CodeChallengeMethod == "" {
			authority.CodeChallengeMethod = authorityDefaultCodeChallengeMethod
		}
		if authority.IdentityClaimName == "" {
			authority.IdentityClaimName = authorityDefaultIdentityClaimName
		}

	default:
		return fmt.Errorf("unknown authority type: %v", authority.AuthorityType)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.authorities[authority.ID] = authority

	return nil
}

// Get returns the registered authorities registration for the provided client ID.
func (r *Registry) Get(ctx context.Context, authorityID string) (*AuthorityRegistration, bool) {
	if authorityID == "" {
		return nil, false
	}

	// Lookup authority registration.
	r.mutex.RLock()
	registration, ok := r.authorities[authorityID]
	r.mutex.RUnlock()

	return registration, ok
}

// Default returns the default authority from the associated registry if any.
func (r *Registry) Default(ctx context.Context) *AuthorityRegistration {
	authority, _ := r.Get(ctx, r.defaultID)
	return authority
}
