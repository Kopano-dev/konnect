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

	"stash.kopano.io/kc/konnect/managers"

	identifierClients "stash.kopano.io/kc/konnect/identifier/clients"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
	codeManagers "stash.kopano.io/kc/konnect/oidc/code/managers"
)

func newManagers(ctx context.Context, bs *bootstrap) (*managers.Managers, error) {
	logger := bs.cfg.Logger

	var err error
	mgrs := managers.New()

	// Encryption manager.
	encryption, err := identityManagers.NewEncryptionManager(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %v", err)
	}
	encryption.SetKey(bs.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid --encryption-secret parameter value for encryption: %v", err)
	}
	mgrs.Set("encryption", encryption)
	logger.Infof("encryption set up with %d key size", encryption.GetKeySize())

	// OIDC code manage.
	code := codeManagers.NewMemoryMapManager(ctx)
	mgrs.Set("code", code)

	// Identifier client registry manager.
	clients, err := identifierClients.NewRegistry(bs.issuerIdentifierURI, bs.identifierRegistrationConf, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create client registry: %v", err)
	}
	mgrs.Set("clients", clients)

	return mgrs, nil
}
