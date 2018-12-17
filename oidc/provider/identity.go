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

package provider

import (
	"errors"

	"github.com/dgrijalva/jwt-go"

	"stash.kopano.io/kc/konnect/identity"
)

func (p *Provider) getIdentityManagerFromClaims(identityProvider string, identityClaims jwt.MapClaims) (identity.Manager, error) {
	if identityClaims == nil {
		// Return default manager when no claims.
		return p.identityManager, nil
	}

	if identityProvider == "" {
		// Return default manager when empty (backwards compatibility).
		return p.identityManager, nil
	}

	if identityProvider == p.identityManager.Name() {
		return p.identityManager, nil
	}
	if p.guestManager != nil && identityProvider == p.guestManager.Name() {
		return p.guestManager, nil
	}

	return nil, errors.New("identity provider mismatch")
}
