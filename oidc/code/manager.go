/*
 * Copyright 2017 Kopano and its licensors
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

package code

import (
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

// Manager is a interface defining a code manager.
type Manager interface {
	Create(ar *payload.AuthenticationRequest, auth identity.AuthRecord) (string, error)
	Pop(code string) (*payload.AuthenticationRequest, identity.AuthRecord, bool)
}
