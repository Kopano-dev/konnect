/*
 * Copyright 2017-2019 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/encryption"
	"stash.kopano.io/kc/konnect/server"
)

// Defaults.
const (
	defaultListenAddr           = "127.0.0.1:8777"
	defaultIdentifierClientPath = "./identifier-webapp"
	defaultSigningKeyID         = "default"
	defaultSigningKeyBits       = 2048
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve <identity-manager> [...args]",
		Short: "Start server and listen for requests",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	serveCmd.Flags().String("listen", "", fmt.Sprintf("TCP listen address (default \"%s\")", defaultListenAddr))
	serveCmd.Flags().String("iss", "", "OIDC issuer URL")
	serveCmd.Flags().StringArray("signing-private-key", nil, "Full path to PEM encoded private key file (must match the --signing-method algorithm)")
	serveCmd.Flags().String("signing-kid", "", "Value of kid field to use in created tokens (uniquely identifying the signing-private-key)")
	serveCmd.Flags().String("validation-keys-path", "", "Full path to a folder containg PEM encoded private or public key files used for token validaton (file name without extension is used as kid)")
	serveCmd.Flags().String("encryption-secret", "", fmt.Sprintf("Full path to a file containing a %d bytes secret key", encryption.KeySize))
	serveCmd.Flags().String("signing-method", "PS256", "JWT default signing method")
	serveCmd.Flags().String("uri-base-path", "", "Custom base path for URI endpoints")
	serveCmd.Flags().String("sign-in-uri", "", "Custom redirection URI to sign-in form")
	serveCmd.Flags().String("signed-out-uri", "", "Custom redirection URI to signed-out goodbye page")
	serveCmd.Flags().String("authorization-endpoint-uri", "", "Custom authorization endpoint URI")
	serveCmd.Flags().String("endsession-endpoint-uri", "", "Custom endsession endpoint URI")
	serveCmd.Flags().String("identifier-client-path", "", fmt.Sprintf("Path to the identifier web client base folder (default \"%s\")", defaultIdentifierClientPath))
	serveCmd.Flags().String("identifier-registration-conf", "", "Path to a identifier-registration.yaml configuration file")
	serveCmd.Flags().String("identifier-scopes-conf", "", "Path to a scopes.yaml configuration file")
	serveCmd.Flags().Bool("insecure", false, "Disable TLS certificate and hostname validation")
	serveCmd.Flags().StringArray("trusted-proxy", nil, "Trusted proxy IP or IP network (can be used multiple times)")
	serveCmd.Flags().StringArray("allow-scope", nil, "Allow OAuth 2 scope (can be used multiple times, if not set default scopes are allowed)")
	serveCmd.Flags().Bool("allow-client-guests", false, "Allow sign in of client controlled guest users")
	serveCmd.Flags().Bool("allow-dynamic-client-registration", false, "Allow dynamic OAuth2 client registration")
	serveCmd.Flags().Bool("log-timestamp", true, "Prefix each log line with timestamp")
	serveCmd.Flags().String("log-level", "info", "Log level (one of panic, fatal, error, warn, info or debug)")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logTimestamp, _ := cmd.Flags().GetBool("log-timestamp")
	logLevel, _ := cmd.Flags().GetString("log-level")

	logger, err := newLogger(!logTimestamp, logLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}
	logger.Infoln("serve start")

	bs := &bootstrap{
		cmd:  cmd,
		args: args,

		cfg: &config.Config{
			Logger: logger,
		},
	}
	err = bs.initialize()
	if err != nil {
		return err
	}
	err = bs.setup(ctx)
	if err != nil {
		return err
	}

	srv, err := server.NewServer(&server.Config{
		Config: bs.cfg,

		Handler: bs.managers.Must("handler").(http.Handler),
		Routes:  []server.WithRoutes{bs.managers.Must("identity").(server.WithRoutes)},
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	logger.Infoln("serve started")
	return srv.Serve(ctx)
}
