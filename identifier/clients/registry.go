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

	"github.com/sirupsen/logrus"
)

// Registry implements the registry for registered clients.
type Registry struct {
	trustedURI *url.URL

	logger logrus.FieldLogger
}

// NewRegistry created a new client Registry with the provided parameters.
func NewRegistry(trustedURI *url.URL, logger logrus.FieldLogger) (*Registry, error) {
	return &Registry{
		trustedURI: trustedURI,

		logger: logger,
	}, nil
}

// Lookup returns the cleitns Detail information for the provided id and uri.
func (r *Registry) Lookup(ctx context.Context, id string, uri *url.URL) (*Details, error) {
	// TODO(longsleep): Implement secure clients configuration and check
	// their ID and redirect URI.
	var trusted bool
	var displayName string

	// Implicit trust for web clients running on the same origin as the issuer
	// (ourselves).
	if r.trustedURI != nil {
		if r.trustedURI.Scheme == uri.Scheme && r.trustedURI.Host == uri.Host {
			trusted = true
		}
	}

	// Some hardcoded ID's for testing.
	switch id {
	case "playground-trusted.js":
		trusted = true
		fallthrough
	case "playground.js":
		// Normal playground mode, moting special not trusted.
		displayName = "OIDC Playground"
	}

	uriString := uri.String()

	r.logger.WithFields(logrus.Fields{
		"trusted":   trusted,
		"client_id": id,
		"uri":       uriString,
		"known":     displayName != "",
	}).Debugln("identifier client lookup")

	return &Details{
		ID:          id,
		URI:         uriString,
		DisplayName: displayName,
		Trusted:     trusted,
	}, nil
}
