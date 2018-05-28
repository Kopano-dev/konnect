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
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"stash.kopano.io/kc/konnect/oidc"
)

// Registry implements the registry for registered clients.
type Registry struct {
	mutex sync.RWMutex

	trustedURI *url.URL
	clients    map[string]*ClientRegistration

	logger logrus.FieldLogger
}

// NewRegistry created a new client Registry with the provided parameters.
func NewRegistry(trustedURI *url.URL, registrationConfFilepath string, logger logrus.FieldLogger) (*Registry, error) {
	registryData := &RegistryData{}

	if registrationConfFilepath != "" {
		logger.Debugf("parsing identifier registration conf from %v", registrationConfFilepath)
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
		trustedURI: trustedURI,
		clients:    make(map[string]*ClientRegistration),

		logger: logger,
	}

	for _, client := range registryData.Clients {
		registerErr := r.Register(client)

		fields := logrus.Fields{
			"client_id":          client.ID,
			"with_client_secret": client.Secret != "",
			"trusted":            client.Trusted,
			"insecure":           client.Insecure,
			"application_type":   client.ApplicationType,
			"redirect_uris":      client.RedirectURIs,
			"origins":            client.Origins,
		}

		if registerErr != nil {
			logger.WithError(registerErr).WithFields(fields).Warnln("skipped registration of invalid client")
			continue
		}
		logger.WithFields(fields).Debugln("registered client")
	}

	return r, nil
}

// Register validates the provided client registration and adds the client
// to the accociated registry if valid. Returns error otherwise.
func (r *Registry) Register(client *ClientRegistration) error {
	if client.ID == "" {
		return errors.New("invalid client_id")
	}

	if !client.Insecure && len(client.RedirectURIs) == 0 {
		return errors.New("no redirect_uris")
	}

	switch client.ApplicationType {
	case "":
		client.ApplicationType = oidc.ApplicationTypeWeb
		fallthrough
	case oidc.ApplicationTypeWeb:
		for _, urlString := range client.RedirectURIs {
			// http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
			parsed, _ := url.Parse(urlString)
			if (!client.Insecure && parsed.Scheme != "https") || parsed.Host == "" {
				return fmt.Errorf("invalid redirect_uri %v - make sure to use https when application_type is web", parsed)
			} else if parsed.Host == "localhost" {
				return fmt.Errorf("invalid redirect_uri %v - host must not be localhost", parsed)
			}

			if len(client.Origins) == 0 {
				// Auto add first redirect scheme and host as Origin if no
				// origin is explicitly configured.
				client.Origins = append(client.Origins, parsed.Scheme+"://"+parsed.Host)
			}
		}
		if !client.Insecure && len(client.Origins) == 0 {
			return errors.New("no origins - origin is required when application_type is web")
		}
		// breaks

	case oidc.ApplicationTypeNative:
		// breaks
		for _, urlString := range client.RedirectURIs {
			// http://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
			parsed, _ := url.Parse(urlString)
			if parsed.Scheme == "https" {
				return fmt.Errorf("invalid redirect_uri %v - scheme must not be https when application_type is native", parsed)
			} else if parsed.Scheme == "http" && parsed.Host != "localhost" {
				return fmt.Errorf("invalid redirect_uri %v = http host must be localhost when application_type is native", parsed)
			}
		}
		// breaks

	default:
		return fmt.Errorf("unknown application_type: %v", client.ApplicationType)
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.clients[client.ID] = client
	return nil
}

// Validate checks if the provided client registration data complies to the
// provided parameters and returns error when it does not.
func (r *Registry) Validate(client *ClientRegistration, clientSecret string, redirectURIString string, originURIString string, withoutSecret bool) error {
	if client.ApplicationType == oidc.ApplicationTypeWeb {
		if originURIString != "" && (!client.Insecure || len(client.Origins) > 0) {
			// Compare originURI if it was given.
			originOK := false
			for _, urlString := range client.Origins {
				if urlString == originURIString {
					originOK = true
					break
				}
			}
			if !originOK {
				return fmt.Errorf("invalid origin: %v", originURIString)
			}
		}
	}

	if redirectURIString != "" && (!client.Insecure || len(client.RedirectURIs) > 0) {
		// Make sure to validate the redirect URI unless client is marked insecure
		// and has no configured redirect URIs.
		redirectURIOK := false
		for _, urlString := range client.RedirectURIs {
			if urlString == redirectURIString {
				redirectURIOK = true
				break
			}
		}
		if !redirectURIOK {
			return fmt.Errorf("invalid redirect_uri: %v", redirectURIString)
		}
	}

	if !withoutSecret && client.Secret != "" && subtle.ConstantTimeCompare([]byte(clientSecret), []byte(client.Secret)) != 1 {
		return fmt.Errorf("invalid client_secret")
	}

	return nil
}

// Lookup returns and validates the clients Detail information for the provided
// parameters from the accociated registry.
func (r *Registry) Lookup(ctx context.Context, clientID string, clientSecret string, redirectURI *url.URL, originURIString string, withoutSecret bool) (*Details, error) {
	var err error
	var trusted bool
	var displayName string

	if clientID == "" {
		return nil, fmt.Errorf("invalid client_id")
	}

	originURI, _ := url.Parse(originURIString)

	// Implicit trust for web clients running and redirecting to the same origin
	// as the issuer (ourselves).
	if r.trustedURI != nil {
		for {
			if r.trustedURI.Scheme != redirectURI.Scheme || r.trustedURI.Host != redirectURI.Host {
				break
			}
			if originURI.Scheme != "" && (r.trustedURI.Scheme != originURI.Scheme || r.trustedURI.Host != originURI.Host) {
				break
			}
			trusted = true
			break
		}
	}

	// Lookup client registration.
	r.mutex.RLock()
	registration, _ := r.clients[clientID]
	r.mutex.RUnlock()

	if registration != nil {
		redirectURIBase := &url.URL{
			Scheme: redirectURI.Scheme,
			Host:   redirectURI.Host,
			Path:   redirectURI.Path,
		}
		err = r.Validate(registration, clientSecret, redirectURIBase.String(), originURIString, withoutSecret)
		displayName = registration.Name
		trusted = registration.Trusted
	} else {
		if trusted {
			// Always let in implicitly trusted clients.
			err = nil
		} else {
			err = fmt.Errorf("unknown client_id: %v", clientID)
		}
	}

	if err != nil {
		return nil, err
	}

	redirecURIString := redirectURI.String()

	r.logger.WithFields(logrus.Fields{
		"trusted":      trusted,
		"client_id":    clientID,
		"redirect_uri": redirecURIString,
		"known":        registration != nil,
	}).Debugln("identifier client lookup")

	return &Details{
		ID:          clientID,
		RedirectURI: redirecURIString,
		DisplayName: displayName,
		Trusted:     trusted,
	}, nil
}
