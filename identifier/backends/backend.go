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

package backends

import (
	"context"

	"stash.kopano.io/kc/konnect/identity"
)

// A Backend is an identifier Backend providing functionality to logon and to
// fetch user meta data.
type Backend interface {
	RunWithContext(context.Context) error

	Logon(ctx context.Context, audience string, username string, password string) (success bool, userID *string, sessionRef *string, err error)
	GetUser(ctx context.Context, userID string, sessionRef *string) (user identity.User, err error)

	ResolveUserByUsername(ctx context.Context, username string) (user identity.UserWithUsername, err error)

	RefreshSession(ctx context.Context, userID string, sessionRef *string) error
	DestroySession(ctx context.Context, sessionRef *string) error

	UserClaims(userID string, authorizedScopes map[string]bool) map[string]interface{}
	ScopesSupported() []string

	Name() string
}
