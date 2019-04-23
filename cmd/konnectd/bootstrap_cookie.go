/*
 * Copyright 2018 Kopano and its licensors
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
