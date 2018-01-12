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
	"os"

	"stash.kopano.io/kc/konnect/identifier"
	identifierBackends "stash.kopano.io/kc/konnect/identifier/backends"
	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
)

func newLDAPIdentityManager(bs *bootstrap) (identity.Manager, error) {
	logger := bs.cfg.Logger

	if bs.authorizationEndpointURI.String() != "" {
		return nil, fmt.Errorf("ldap backend is incompatible with authorization-endpoint-uri parameter")
	}
	bs.authorizationEndpointURI.Path = "/signin/v1/identifier/_/authorize"

	if bs.signInFormURI.EscapedPath() == "" {
		bs.signInFormURI.Path = "/signin/v1/identifier"
	}

	identifierBackend, identifierErr := identifierBackends.NewLDAPIdentifierBackend(
		bs.cfg,
		bs.tlsClientConfig,
		os.Getenv("LDAP_URI"),
		os.Getenv("LDAP_BINDDN"),
		os.Getenv("LDAP_BINDPW"),
		os.Getenv("LDAP_BASEDN"),
		os.Getenv("LDAP_SCOPE"),
		os.Getenv("LDAP_LOGIN_ATTRIBUTE"),
		os.Getenv("LDAP_EMAIL_ATTRIBUTE"),
		os.Getenv("LDAP_NAME_ATTRIBUTE"),
		os.Getenv("LDAP_FILTER"),
	)
	if identifierErr != nil {
		return nil, fmt.Errorf("failed to create identifier backend: %v", identifierErr)
	}

	fullAuthorizationEndpointURL, _ := url.Parse(bs.issuerIdentifierURI.String())
	fullAuthorizationEndpointURL.Path = bs.authorizationEndpointURI.Path

	activeIdentifier, err := identifier.NewIdentifier(&identifier.Config{
		Config: bs.cfg,

		PathPrefix:      "/signin/v1",
		StaticFolder:    bs.identifierClientPath,
		LogonCookieName: "__Secure-KKT", // Kopano-Konnect-Token

		AuthorizationEndpointURI: fullAuthorizationEndpointURL,

		Backend: identifierBackend,
		Clients: bs.managers.clients,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create identifier: %v", err)
	}
	err = activeIdentifier.SetKey(bs.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid --encryption-secret parameter value for identifier: %v", err)
	}

	identityManagerConfig := &identity.Config{
		SignInFormURI: bs.signInFormURI,

		Logger: logger,
	}

	identifierIdentityManager := identityManagers.NewIdentifierIdentityManager(identityManagerConfig, activeIdentifier, bs.managers.clients)
	logger.Infoln("using identifier backed identity manager")

	return identifierIdentityManager, nil
}
