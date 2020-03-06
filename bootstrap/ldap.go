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

package bootstrap

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
	bs.authorizationEndpointURI.Path = bs.makeURIPath(apiTypeSignin, "/identifier/_/authorize")

	if bs.endSessionEndpointURI.String() != "" {
		return nil, fmt.Errorf("ldap backend is incompatible with endsession-endpoint-uri parameter")
	}
	bs.endSessionEndpointURI.Path = bs.makeURIPath(apiTypeSignin, "/identifier/_/endsession")

	if bs.signInFormURI.EscapedPath() == "" {
		bs.signInFormURI.Path = bs.makeURIPath(apiTypeSignin, "/identifier")
	}

	if bs.signedOutURI.EscapedPath() == "" {
		bs.signedOutURI.Path = bs.makeURIPath(apiTypeSignin, "/goodbye")
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

		BaseURI:         bs.issuerIdentifierURI,
		PathPrefix:      bs.makeURIPath(apiTypeSignin, ""),
		StaticFolder:    bs.identifierClientPath,
		LogonCookieName: "__Secure-KKT", // Kopano-Konnect-Token
		ScopesConf:      bs.identifierScopesConf,
		WebAppDisabled:  bs.identifierClientDisabled,

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
