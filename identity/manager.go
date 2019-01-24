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

	"github.com/gorilla/mux"

	"stash.kopano.io/kc/konnect/identity/clients"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

// Manager is a interface to define a identity manager.
type Manager interface {
	Authenticate(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, next Manager) (AuthRecord, error)
	Authorize(ctx context.Context, rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth AuthRecord) (AuthRecord, error)
	EndSession(ctx context.Context, rw http.ResponseWriter, req *http.Request, esr *payload.EndSessionRequest) error

	ApproveScopes(ctx context.Context, sub string, audience string, approvedScopesList map[string]bool) (string, error)
	ApprovedScopes(ctx context.Context, sub string, audience string, ref string) (map[string]bool, error)

	Fetch(ctx context.Context, userID string, sessionRef *string, scopes map[string]bool, requestedClaimsMaps []*payload.ClaimsRequestMap) (AuthRecord, bool, error)

	Name() string
	ScopesSupported(scopes map[string]bool) []string
	ClaimsSupported(claims []string) []string

	AddRoutes(ctx context.Context, router *mux.Router)

	OnSetLogon(func(ctx context.Context, rw http.ResponseWriter, user User) error) error
	OnUnsetLogon(func(ctx context.Context, rw http.ResponseWriter) error) error

	GetClientRegistration(ctx context.Context, clientID string) (*clients.ClientRegistration, bool)
}
