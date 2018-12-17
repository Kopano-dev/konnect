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
	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
)

func newGuestIdentityManager(bs *bootstrap) (identity.Manager, error) {
	logger := bs.cfg.Logger

	identityManagerConfig := &identity.Config{
		Logger: logger,
	}

	guestIdentityManager := identityManagers.NewGuestIdentityManager(identityManagerConfig)

	return guestIdentityManager, nil
}
