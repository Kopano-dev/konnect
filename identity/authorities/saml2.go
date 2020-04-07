/*
 * Copyright 2017-2020 Kopano and its licensors
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
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/sirupsen/logrus"

	"stash.kopano.io/kc/konnect/utils"
)

type saml2AuthorityRegistration struct {
	registry *Registry
	data     *authorityRegistrationData

	discover         bool
	metadataEndpoint *url.URL

	mutex sync.RWMutex
	ready bool

	serviceProvider *saml.ServiceProvider
}

func newSAML2AuthorityRegistration(registry *Registry, registrationData *authorityRegistrationData) (*saml2AuthorityRegistration, error) {
	ar := &saml2AuthorityRegistration{
		registry: registry,
		data:     registrationData,
	}

	if ar.data.RawMetadataEndpoint != "" {
		if u, err := url.Parse(ar.data.RawMetadataEndpoint); err == nil {
			ar.metadataEndpoint = u
		} else {
			return nil, fmt.Errorf("invalid metadata_endpoint value: %w", err)
		}
	}

	if ar.data.EntityID == "" {
		return nil, errors.New("no entity_id")
	}

	if ar.data.Discover != nil {
		ar.discover = *ar.data.Discover
	}

	if !ar.discover {
		return nil, errors.New("saml2 must use discover")
	}

	return ar, nil
}

func (ar *saml2AuthorityRegistration) ID() string {
	return ar.data.ID
}

func (ar *saml2AuthorityRegistration) Name() string {
	return ar.data.Name
}

func (ar *saml2AuthorityRegistration) AuthorityType() string {
	return ar.data.AuthorityType
}

func (ar *saml2AuthorityRegistration) Authority() *Details {
	details := &Details{
		ID:            ar.data.ID,
		Name:          ar.data.Name,
		AuthorityType: ar.data.AuthorityType,

		Trusted:  ar.data.Trusted,
		Insecure: ar.data.Insecure,

		registration: ar,
	}

	ar.mutex.RLock()
	details.ready = ar.ready
	ar.mutex.RUnlock()

	return details
}

func (ar *saml2AuthorityRegistration) Validate() error {
	return nil
}

func (ar *saml2AuthorityRegistration) Initialize(ctx context.Context, registry *Registry) error {
	ar.mutex.Lock()
	defer ar.mutex.Unlock()

	if ar.metadataEndpoint == nil {
		return fmt.Errorf("no metadata_endpoint set")
	}
	if ar.data.EntityID == "" {
		return fmt.Errorf("no entity_id set")
	}

	logger := registry.logger.WithFields(logrus.Fields{
		"id":   ar.data.ID,
		"type": AuthorityTypeSAML2,
	})

	var client *http.Client
	if ar.data.Insecure {
		client = utils.InsecureHTTPClient
	} else {
		client = utils.DefaultHTTPClient
	}

	baseURIString := registry.baseURI.String()
	acsURL, _ := url.Parse(baseURIString + "/identifier/saml2/acs")   // Assertion Consumer Service
	sloURL, _ := url.Parse(baseURIString + "/identifier/_/saml2/slo") // Single Logout Service
	logger.WithFields(logrus.Fields{
		"entity_id":         ar.data.EntityID,
		"metadata_endpoint": ar.data.RawMetadataEndpoint,
		"acs_url":           acsURL.String(),
		"slo_url":           sloURL.String(),
	}).Infoln("setting up external saml2 authority")

	go func() {
		var md *saml.EntityDescriptor
		var err error
		for {
			md, err = samlsp.FetchMetadata(ctx, client, *ar.metadataEndpoint)
			if err != nil {
				logger.Errorf("error while saml2 provider meta data update: %v", err)
				return
			}

			if md != nil {
				ar.mutex.Lock()

				ar.serviceProvider = &saml.ServiceProvider{
					EntityID:          ar.data.EntityID,
					AcsURL:            *acsURL,
					SloURL:            *sloURL,
					IDPMetadata:       md,
					AllowIDPInitiated: false,
				}

				ready := ar.ready
				if ar.serviceProvider != nil {
					ar.ready = true
				} else {
					ar.ready = false
				}
				if ready != ar.ready {
					if ar.ready {
						logger.Infoln("authority is now ready")
					} else {
						logger.Warnln("authority is no longer ready")
					}
				} else if !ar.ready {
					logger.Warnln("authority not ready")
				}

				ready = ar.ready

				ar.mutex.Unlock()

				if ready {
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				// breaks
			}
		}
	}()

	return nil
}

func (ar *saml2AuthorityRegistration) IdentityClaimValue(rawAssertion interface{}) (string, error) {
	assertion, _ := rawAssertion.(*saml.Assertion)
	if assertion == nil {
		return "", errors.New("invalid assertion data")
	}

	icn := ar.data.IdentityClaimName
	if icn == "" {
		icn = "uid" // TODO(longsleep): Use constant.
	}

	var cvs string
	var ok bool
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attr := range attributeStatement.Attributes {
			values := []string{}
			for _, value := range attr.Values {
				values = append(values, value.Value)
			}
			ar.registry.logger.WithFields(logrus.Fields{
				"FriendlyName": attr.FriendlyName,
				"Name":         attr.Name,
				"NameFormat":   attr.NameFormat,
				"Values":       values,
			}).Debugln("saml2 attributeStatement")

			if !ok {
				claimName := attr.FriendlyName
				if claimName == "" {
					claimName = attr.Name
				}
				if claimName == icn && len(values) == 1 {
					if attr.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:basic" {
						ar.registry.logger.WithField("NameFormat", attr.NameFormat).Warnln("saml2 ignoring unsupported name format for identity claim name")
						continue
					}
					cvs = values[0]
					ok = true
				}
			}
		}
	}

	if !ok {
		return "", errors.New("identity claim not found")
	}

	// Convert claim value.
	whitelisted := false
	if ar.data.IdentityAliases != nil {
		if alias, ok := ar.data.IdentityAliases[cvs]; ok && alias != "" {
			cvs = alias
			whitelisted = true
		}
	}

	// Check whitelist.
	if ar.data.IdentityAliasRequired && !whitelisted {
		return "", errors.New("identity claim has no alias")
	}

	return cvs, nil
}

func (ar *saml2AuthorityRegistration) Issuer() string {
	return ar.metadataEndpoint.String()
}

func (ar *saml2AuthorityRegistration) MakeRedirectAuthenticationRequestURL(state string) (*url.URL, map[string]interface{}, error) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	if !ar.ready {
		return nil, nil, errors.New("not ready")
	}

	authReq, err := ar.serviceProvider.MakeAuthenticationRequest(ar.serviceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding))
	if err != nil {
		return nil, nil, err
	}

	uri := authReq.Redirect(state)
	return uri, map[string]interface{}{
		"rid": authReq.ID,
	}, nil
}

func (ar *saml2AuthorityRegistration) ParseStateResponse(req *http.Request, state string, extra map[string]interface{}) (interface{}, error) {
	requestID := extra["rid"].(string)

	return ar.serviceProvider.ParseResponse(req, []string{requestID})
}

func (ar *saml2AuthorityRegistration) MakeRedirectLogoutRequestURL(req interface{}, state string) (*url.URL, map[string]interface{}, error) {
	ar.mutex.RLock()
	defer ar.mutex.RUnlock()

	if !ar.ready {
		return nil, nil, errors.New("not ready")
	}

	// TODO(longsleep): Implement extration of URL from RelayState.
	return nil, nil, nil
}

func (ar *saml2AuthorityRegistration) Metadata() interface{} {
	metadata := ar.serviceProvider.Metadata()

	// Set SLO to use redirect binding.
	metadata.SPSSODescriptors[0].SSODescriptor.SingleLogoutServices = []saml.Endpoint{
		{
			Binding:  saml.HTTPRedirectBinding,
			Location: ar.serviceProvider.SloURL.String(),
		},
	}

	return metadata
}
