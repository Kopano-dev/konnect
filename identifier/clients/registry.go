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

package clients

import (
	"context"
	"net/url"
)

// Registry implements the registry for registered clients.
type Registry struct{}

// Lookup returns the cleitns Detail information for the provided id and uri.
func (r *Registry) Lookup(ctx context.Context, id string, uri *url.URL) (*Details, error) {
	// TODO(longsleep): Implement secure clients configuration and check
	// their ID and redirect URI.
	// TODO(longsleep): Implement implicit trust for web clients running on
	// the same origin as the issuer (ourselves).
	var trusted bool
	var displayName string

	// Some hardcoded ID's for testing.
	switch id {
	case "playground-trusted.js":
		trusted = true
		fallthrough
	case "playground.js":
		// Normal playground mode, moting special not trusted.
		displayName = "OIDC Playground"
	}

	return &Details{
		ID:          id,
		URI:         uri.String(),
		DisplayName: displayName,
		Trusted:     trusted,
	}, nil
}
