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

	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
	codeManagers "stash.kopano.io/kc/konnect/oidc/code/managers"
	"stash.kopano.io/kc/konnect/oidc/provider"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

func newTestServer(ctx context.Context, t *testing.T) (*httptest.Server, *Server, http.Handler, *Config) {
	p, err := provider.NewProvider(&provider.Config{
		IssuerIdentifier:  "http://localhost:8777",
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: "/konnect/v1/authorize",
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",

		IdentityManager: &identityManagers.DummyIdentityManager{
			Sub: "unittestuser",
		},
		CodeManager: codeManagers.NewMemoryMapManager(ctx),
		Logger:      logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	config := &Config{
		Logger:   logger,
		Provider: p,
	}

	server, err := NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	router := mux.NewRouter()
	server.AddRoutes(ctx, router)

	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		router.ServeHTTP(rw, req)
	}))

	return s, server, router, config
}

func TestNewTestServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	newTestServer(ctx, t)
}
