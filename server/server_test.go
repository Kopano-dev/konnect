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
	"os"
	"testing"

	"stash.kopano.io/kc/konnect/oidc/provider"

	"github.com/sirupsen/logrus"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

func newTestServer(ctx context.Context, t *testing.T) (*httptest.Server, *Server) {
	var server *Server

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
	}))

	config := &Config{
		Logger: logger,

		Provider: provider.NewProvider(ctx, &provider.Config{
			IssuerIdentifier:  "http://localhost:8777",
			WellKnownPath:     "/.well-known/openid-configuration",
			JwksPath:          "/konnect/v1/jwks.json",
			AuthorizationPath: "/konnect/v1/authorize",
			TokenPath:         "/konnect/v1/token",
			UserInfoPath:      "/konnect/v1/userinfo",

			Logger: logger,
		}),
	}

	var err error
	server, err = NewServer(ctx, config)
	if err != nil {
		t.Fatal(err)
	}

	return s, server
}

func TestNewTestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newTestServer(ctx, t)
}
