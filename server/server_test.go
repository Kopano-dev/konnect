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
	"net/http/httptest"
	"testing"
)

func newTestServer(ctx context.Context, t *testing.T) (*httptest.Server, *Server) {
	server, err := NewServer(ctx)
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
	}))

	return s, server
}

func TestNewTestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newTestServer(ctx, t)
}
