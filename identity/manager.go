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
	"context"
	"net/http"

	"stash.kopano.io/kc/konnect/oidc/payload"
)

// Manager is a interface to define a identity manager.
type Manager interface {
	Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest) (AuthRecord, error)
	Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth AuthRecord) (AuthRecord, error)

	Fetch(ctx context.Context, userID string, scopes map[string]bool) (AuthRecord, bool, error)

	ScopesSupported() []string
	ClaimsSupported() []string
}
