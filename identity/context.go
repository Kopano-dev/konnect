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
)

// key is an unexported type for keys defined in this package.
// This prevents collisions with keys defined in other packages.
type key int

// authRecordKey is the key for identity.AuthRecord in Contexts. It is
// unexported; clients use identity.NewContext and identity.FromContext
// instead of using this key directly.
var authRecordKey key

// NewContext returns a new Context that carries value auth.
func NewContext(ctx context.Context, auth AuthRecord) context.Context {
	return context.WithValue(ctx, authRecordKey, auth)
}

// FromContext returns the AuthRecord value stored in ctx, if any.
func FromContext(ctx context.Context) (AuthRecord, bool) {
	auth, ok := ctx.Value(authRecordKey).(AuthRecord)
	return auth, ok
}
