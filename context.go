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

package konnect

import (
	"context"
)

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// accessTokenClaimsKey is the key for AccessTokenClaims in Contexts. It is
// unexported; clients use konnect.NewAccessTokenContext and
// connect.FromAccessTokenContext instead of using this key directly.
var accessTokenClaimsKey key

// NewAccessTokenContext returns a new Context that carries value auth.
func NewAccessTokenContext(ctx context.Context, claims *AccessTokenClaims) context.Context {
	return context.WithValue(ctx, accessTokenClaimsKey, claims)
}

// FromAccessTokenContext returns the AuthRecord value stored in ctx, if any.
func FromAccessTokenContext(ctx context.Context) (*AccessTokenClaims, bool) {
	claims, ok := ctx.Value(accessTokenClaimsKey).(*AccessTokenClaims)
	return claims, ok
}
