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
	"os"
	"strings"

	"stash.kopano.io/kc/konnect/identifier"
	identifierBackends "stash.kopano.io/kc/konnect/identifier/backends"
	ldapDefinitions "stash.kopano.io/kc/konnect/identifier/backends/ldap"
	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
)

func newLDAPIdentityManager(bs *bootstrap) (identity.Manager, error) {
	logger := bs.cfg.Logger

	if bs.authorizationEndpointURI.String() != "" {
		return nil, fmt.Errorf("ldap backend is incompatible with authorization-endpoint-uri parameter")
	}
	bs.authorizationEndpointURI.Path = "/signin/v1/identifier/_/authorize"

	if bs.endSessionEndpointURI.String() != "" {
		return nil, fmt.Errorf("ldap backend is incompatible with endsession-endpoint-uri parameter")
	}
	bs.endSessionEndpointURI.Path = "/signin/v1/identifier/_/endsession"

	if bs.signInFormURI.EscapedPath() == "" {
		bs.signInFormURI.Path = "/signin/v1/identifier"
	}

	if bs.signedOutURI.EscapedPath() == "" {
		bs.signedOutURI.Path = "/signin/v1/goodbye"
	}

	// Default LDAP attribute mappings.
	attributeMapping := map[string]string{
		ldapDefinitions.AttributeLogin:                        os.Getenv("LDAP_LOGIN_ATTRIBUTE"),
		ldapDefinitions.AttributeEmail:                        os.Getenv("LDAP_EMAIL_ATTRIBUTE"),
		ldapDefinitions.AttributeName:                         os.Getenv("LDAP_NAME_ATTRIBUTE"),
		ldapDefinitions.AttributeFamilyName:                   os.Getenv("LDAP_FAMILY_NAME_ATTRIBUTE"),
		ldapDefinitions.AttributeGivenName:                    os.Getenv("LDAP_GIVEN_NAME_ATTRIBUTE"),
		ldapDefinitions.AttributeUUID:                         os.Getenv("LDAP_UUID_ATTRIBUTE"),
		fmt.Sprintf("%s_type", ldapDefinitions.AttributeUUID): os.Getenv("LDAP_UUID_ATTRIBUTE_TYPE"),
	}
	// Add optional LDAP attribute mappings.
	if numericUIDAttribute := os.Getenv("LDAP_UIDNUMBER_ATTRIBUTE"); numericUIDAttribute != "" {
		attributeMapping[ldapDefinitions.AttributeNumericUID] = numericUIDAttribute
	}
	// Sub from LDAP attribute mappings.
	var subMapping []string
	if subMappingString := os.Getenv("LDAP_SUB_ATTRIBUTES"); subMappingString != "" {
		subMapping = strings.Split(subMappingString, " ")
	}

	identifierBackend, identifierErr := identifierBackends.NewLDAPIdentifierBackend(
		bs.cfg,
		bs.tlsClientConfig,
		os.Getenv("LDAP_URI"),
		os.Getenv("LDAP_BINDDN"),
		os.Getenv("LDAP_BINDPW"),
		os.Getenv("LDAP_BASEDN"),
		os.Getenv("LDAP_SCOPE"),
		os.Getenv("LDAP_FILTER"),
		subMapping,
		attributeMapping,
	)
	if identifierErr != nil {
		return nil, fmt.Errorf("failed to create identifier backend: %v", identifierErr)
	}

	fullAuthorizationEndpointURL := withSchemeAndHost(bs.authorizationEndpointURI, bs.issuerIdentifierURI)

	activeIdentifier, err := identifier.NewIdentifier(&identifier.Config{
		Config: bs.cfg,

		PathPrefix:      "/signin/v1",
		StaticFolder:    bs.identifierClientPath,
		LogonCookieName: "__Secure-KKT", // Kopano-Konnect-Token
		ScopesConf:      bs.identifierScopesConf,

		AuthorizationEndpointURI: fullAuthorizationEndpointURL,

		Backend: identifierBackend,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create identifier: %v", err)
	}
	err = activeIdentifier.SetKey(bs.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid --encryption-secret parameter value for identifier: %v", err)
	}

	identityManagerConfig := &identity.Config{
		SignInFormURI: withSchemeAndHost(bs.signInFormURI, bs.issuerIdentifierURI),
		SignedOutURI:  withSchemeAndHost(bs.signedOutURI, bs.issuerIdentifierURI),

		Logger: logger,

		ScopesSupported: bs.cfg.AllowedScopes,
	}

	identifierIdentityManager := identityManagers.NewIdentifierIdentityManager(identityManagerConfig, activeIdentifier)
	logger.Infoln("using identifier backed identity manager")

	return identifierIdentityManager, nil
}
