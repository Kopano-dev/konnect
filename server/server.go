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

	"github.com/gorilla/mux"
)

// Server is our HTTP server implementation.
type Server struct {
	mux http.Handler
}

// NewServer constructs a server from the provided parameters.
func NewServer(ctx context.Context) (*Server, error) {
	s := &Server{}

	router := mux.NewRouter()
	s.mux = router

	return s, nil
}

// ServeHTTP implements the http.HandlerFunc interface.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
