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

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"

	"stash.kopano.io/kc/konnect/identity/managers"
	"stash.kopano.io/kc/konnect/oidc/provider"
	"stash.kopano.io/kc/konnect/server"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start server and listen for requests",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	}
	serveCmd.Flags().String("listen", "127.0.0.1:8777", "TCP listen address")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger, err := newLogger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}

	logger.Infoln("Using dummy identity manager")
	identityManager := &managers.DummyIdentityManager{
		UserID: "dummy",
	}

	listenAddr, _ := cmd.Flags().GetString("listen")

	p, err := provider.NewProvider(&provider.Config{
		IssuerIdentifier:  "http://localhost:8777",
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: "/konnect/v1/authorize",
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",

		IdentityManager: identityManager,
		Logger:          logger,
	})
	if err != nil {
		return fmt.Errorf("failed to create provider: %v", err)
	}

	config := &server.Config{
		ListenAddr: listenAddr,
		Logger:     logger,
		Provider:   p,
	}

	srv, err := server.NewServer(config)
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	func() {
		//XXX(longsleep): remove me - create keypair for testing.
		key, _ := rsa.GenerateKey(rand.Reader, 512)
		srv.Provider.SetSigningKey("default", key, jwt.SigningMethodRS256)
		logger.Infoln("created random RSA key pair")
	}()

	return srv.Serve(ctx)
}
