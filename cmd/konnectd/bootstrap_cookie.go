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

package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
)

func newCookieIdentityManager(bs *bootstrap) (identity.Manager, error) {
	logger := bs.cfg.Logger

	if bs.authorizationEndpointURI.EscapedPath() == "" {
		bs.authorizationEndpointURI.Path = bs.makeURIPath(apiTypeKonnect, "/authorize")
	}

	if !strings.HasPrefix(bs.signInFormURI.EscapedPath(), "/") {
		return nil, fmt.Errorf("URI path must be absolute")
	}

	if len(bs.args) < 2 {
		return nil, fmt.Errorf("cookie backend requires the backend URI as argument")
	}
	backendURI, backendURIErr := url.Parse(bs.args[1])
	if backendURIErr != nil || !backendURI.IsAbs() {
		if backendURIErr == nil {
			backendURIErr = fmt.Errorf("URI must have a scheme")
		}
		return nil, fmt.Errorf("invalid backend URI, %v", backendURIErr)
	}

	var cookieNames []string
	if len(bs.args) > 2 {
		// TODO(longsleep): Add proper usage help.
		cookieNames = bs.args[2:]
	}

	identityManagerConfig := &identity.Config{
		SignInFormURI: bs.signInFormURI,

		Logger: logger,

		ScopesSupported: bs.cfg.AllowedScopes,
	}

	cookieIdentityManager := identityManagers.NewCookieIdentityManager(identityManagerConfig, backendURI, cookieNames, 30*time.Second, bs.cfg.HTTPTransport)
	logger.WithFields(logrus.Fields{
		"backend": backendURI,
		"signIn":  bs.signInFormURI,
		"cookies": cookieNames,
	}).Infoln("using cookie backed identity manager")

	return cookieIdentityManager, nil
}
