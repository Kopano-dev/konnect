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

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
)

// PublicSubjectFromAuth creates the provideds auth Subject value with the
// accociated provider. This subject can be used as URL safe value to uniquely
// identify the provided auth user with remote systems.
func (p *Provider) PublicSubjectFromAuth(auth identity.AuthRecord) (string, error) {
	authorizedScopes := auth.AuthorizedScopes()
	if ok, _ := authorizedScopes[konnect.ScopeRawSubject]; ok {
		// Return raw subject as is when with ScopeRawSubject.
		user := auth.User()
		if user == nil {
			return "", errors.New("no user")
		}

		return user.Raw(), nil
	}

	return auth.Subject(), nil
}
