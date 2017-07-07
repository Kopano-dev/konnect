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

package identity

import (
	"github.com/dgrijalva/jwt-go"
)

// AuthRecord is an interface which provides identity auth information with scopes and claims..
type AuthRecord interface {
	UserID() string
	AuthorizedScopes() map[string]bool
	AuthorizeScopes(map[string]bool)
	Claims(...string) []jwt.Claims

	User() User
	SetUser(User)
}
