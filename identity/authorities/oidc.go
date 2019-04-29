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
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2"
	"stash.kopano.io/kgol/oidc-go"

	"stash.kopano.io/kc/konnect/utils"
)

type oidcProviderLogger struct {
	logger logrus.FieldLogger
}

func (logger *oidcProviderLogger) Printf(format string, args ...interface{}) {
	logger.logger.Debugf(format, args...)
}

func initializeOIDC(ctx context.Context, logger logrus.FieldLogger, ar *AuthorityRegistration) error {
	providerLogger := logger.WithFields(logrus.Fields{
		"id":   ar.ID,
		"type": AuthorityTypeOIDC,
	})
	config := &oidc.ProviderConfig{
		Logger:     &oidcProviderLogger{providerLogger},
		HTTPHeader: http.Header{},
	}
	if ar.Insecure {
		config.HTTPClient = utils.InsecureHTTPClient
	} else {
		config.HTTPClient = utils.DefaultHTTPClient
	}
	config.HTTPHeader.Set("User-Agent", utils.DefaultHTTPUserAgent)

	issuer, err := url.Parse(ar.Iss)
	if err != nil {
		return fmt.Errorf("failed to parse issuer: %v", err)
	}
	if issuer.Scheme != "https" {
		return fmt.Errorf("issuer scheme is not https")
	}
	if issuer.Host == "" {
		return fmt.Errorf("issuer host is empty")
	}
	provider, err := oidc.NewProvider(issuer, config)
	if err != nil {
		return fmt.Errorf("failed to create oidc provider: %v", err)
	}
	updates := make(chan *oidc.ProviderDefinition)
	errors := make(chan error)
	err = provider.Initialize(ctx, updates, errors)
	if err != nil {
		return fmt.Errorf("failed to initialize oidc provider: %v", err)
	}
	go func() {
		// Handle updates and errors of authority meta data.
		var pd *oidc.ProviderDefinition
		var jwks *jose.JSONWebKeySet
		for {
			pd = nil

			select {
			case <-ctx.Done():
				return
			case update := <-updates:
				pd = update
			case err := <-errors:
				providerLogger.Errorf("error while oidc provider update: %v", err)
			}

			if pd != nil {
				ar.mutex.Lock()

				if pd.WellKnown != nil && pd.WellKnown.AuthorizationEndpoint != "" {
					if ar.authorizationEndpoint, err = url.Parse(pd.WellKnown.AuthorizationEndpoint); err != nil {
						providerLogger.WithError(err).Errorln("failed to parse oidc provider discover document authorization_endpoint")
					}
				}

				if pd.JWKS != jwks {
					if err := ar.setValidationKeysFromJWKS(pd.JWKS, true); err != nil {
						providerLogger.Errorf("failed to set authority keys from oidc provider jwks: %v", err)
					}
				}

				ready := ar.ready
				if ar.authorizationEndpoint != nil && ar.validationKeys != nil {
					ar.ready = true
				} else {
					ar.ready = false
				}
				if ready != ar.ready {
					if ar.ready {
						providerLogger.Infoln("authority is now ready")
					} else {
						providerLogger.Warnln("authority is no longer ready")
					}
				} else if !ar.ready {
					providerLogger.Warnln("authority not ready")
				}

				ar.mutex.Unlock()
			}
		}
	}()

	return nil
}
