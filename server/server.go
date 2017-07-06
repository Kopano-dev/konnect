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

package server

import (
	"context"
	"net/http"

	"stash.kopano.io/kc/konnect/oidc/provider"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Server is our HTTP server implementation.
type Server struct {
	*provider.Provider

	mux    http.Handler
	logger logrus.FieldLogger
}

// NewServer constructs a server from the provided parameters.
func NewServer(ctx context.Context, c *Config) (*Server, error) {
	// TODO(longsleep): Add subpath support to all handlers and paths.

	s := &Server{
		Provider: c.Provider,

		logger: c.Logger,
	}

	router := mux.NewRouter()
	router.HandleFunc("/health-check", s.HealthCheckHandler)
	// Delegate to provider which is also a handler.
	router.NotFoundHandler = s.Provider
	s.mux = router

	return s, nil
}

// ServeHTTP implements the http.HandlerFunc interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
