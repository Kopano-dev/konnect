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
	"context"
	"fmt"
	"net/http"

	identifierClients "stash.kopano.io/kc/konnect/identifier/clients"
	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
	"stash.kopano.io/kc/konnect/oidc/code"
	codeManagers "stash.kopano.io/kc/konnect/oidc/code/managers"
)

type managers struct {
	encryption *identityManagers.EncryptionManager
	code       code.Manager
	clients    *identifierClients.Registry

	identity identity.Manager
	handler  http.Handler
}

func newManagers(ctx context.Context, identityManagerName string, bs *bootstrap) (*managers, error) {
	logger := bs.cfg.Logger

	var err error
	managers := &managers{}

	// Encryption manager.
	managers.encryption, err = identityManagers.NewEncryptionManager(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %v", err)
	}
	err = managers.encryption.SetKey(bs.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid --encryption-secret parameter value for encryption: %v", err)
	}
	logger.Infof("encryption set up with %d key size", managers.encryption.GetKeySize())

	// OIDC code manage.
	managers.code = codeManagers.NewMemoryMapManager(ctx)

	// Identifier client registry manager.
	managers.clients, _ = identifierClients.NewRegistry(bs.issuerIdentifierURI, logger)

	return managers, nil
}
