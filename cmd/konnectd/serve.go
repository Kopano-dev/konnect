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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	kcc "stash.kopano.io/kgol/kcc-go"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/encryption"
	"stash.kopano.io/kc/konnect/identifier"
	identifierBackends "stash.kopano.io/kc/konnect/identifier/backends"
	"stash.kopano.io/kc/konnect/identity"
	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
	codeManagers "stash.kopano.io/kc/konnect/oidc/code/managers"
	"stash.kopano.io/kc/konnect/oidc/provider"
	"stash.kopano.io/kc/konnect/server"
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
	serveCmd.Flags().String("listen", "127.0.0.1:8777", "TCP listen address")
	serveCmd.Flags().String("iss", "http://localhost:8777", "OIDC issuer URL")
	serveCmd.Flags().String("key", "", "PEM key file (RSA)")
	serveCmd.Flags().String("secret", "", fmt.Sprintf("Encryption secret (length must be %d)", encryption.KeySize))
	serveCmd.Flags().String("signing-method", "RS256", "JWT signing method")
	serveCmd.Flags().String("sign-in-uri", "", "Custom redirection URI to sign-in form")
	serveCmd.Flags().String("authorization-endpoint-uri", "", "Custom authorization endpoint URI")
	serveCmd.Flags().Bool("insecure", false, "Disable TLS certificate and hostname validation")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger, err := newLogger()
	if err != nil {
		return fmt.Errorf("failed to create logger: %v", err)
	}
	logger.Infoln("serve start")

	cfg := &config.Config{
		Logger: logger,
	}

	if len(args) == 0 {
		return fmt.Errorf("identity-manager argument missing")
	}
	identityManagerName := args[0]

	signInFormURIString, _ := cmd.Flags().GetString("sign-in-uri")
	signInFormURI, err := url.Parse(signInFormURIString)
	if err != nil {
		return fmt.Errorf("invalid sign-in URI, %v", err)
	}

	authorizationEndpointURIString, _ := cmd.Flags().GetString("authorization-endpoint-uri")
	authorizationEndpointURI, err := url.Parse(authorizationEndpointURIString)
	if err != nil {
		return fmt.Errorf("invalid authorization-endpoint-uri, %v", err)
	}

	tlsInsecureSkipVerify, _ := cmd.Flags().GetBool("insecure")
	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if tlsInsecureSkipVerify {
		// NOTE(longsleep): This disable http2 client support. See https://github.com/golang/go/issues/14275 for reasons.
		httpTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: tlsInsecureSkipVerify,
		}
		logger.Warnln("insecure mode, TLS client connections are susceptible to man-in-the-middle attacks")
		logger.Debugln("http2 client support is disabled (insecure mode)")
	}

	cfg.HTTPTransport = httpTransport

	var encryptionSecret []byte
	if encryptionSecretString, _ := cmd.Flags().GetString("secret"); encryptionSecretString != "" {
		encryptionSecret = []byte(encryptionSecretString)
	} else {
		logger.Warnln("missing --secret parameter, using random encyption secret")
		encryptionSecret = rndm.GenerateRandomBytes(encryption.KeySize)
	}

	var encryptionManager *identityManagers.EncryptionManager
	encryptionManager, err = identityManagers.NewEncryptionManager(nil)
	if err != nil {
		return fmt.Errorf("failed to create encryption manager: %v", err)
	}
	err = encryptionManager.SetKey(encryptionSecret)
	if err != nil {
		return fmt.Errorf("invalid --secret parameter value: %v", err)
	}

	codeManager := codeManagers.NewMemoryMapManager(ctx)

	issuerIdentifier, _ := cmd.Flags().GetString("iss") // TODO(longsleep): Validate iss value.

	var activeIdentifier *identifier.Identifier

	var identityManager identity.Manager
	switch identityManagerName {
	case "cookie":
		if !strings.HasPrefix(signInFormURI.EscapedPath(), "/") {
			return fmt.Errorf("URI path must be absolute")
		}
		if len(args) < 2 {
			return fmt.Errorf("cookie backend requires the backend URI as argument")
		}
		backendURI, backendURIErr := url.Parse(args[1])
		if backendURIErr != nil || !backendURI.IsAbs() {
			if backendURIErr == nil {
				backendURIErr = fmt.Errorf("URI must have a scheme")
			}
			return fmt.Errorf("invalid backend URI, %v", backendURIErr)
		}

		var cookieNames []string
		if len(args) > 2 {
			// TODO(longsleep): Add proper usage help.
			cookieNames = args[2:]
		}

		identityManagerConfig := &identity.Config{
			SignInFormURI: signInFormURI,

			Logger: logger,
		}

		cookieIdentityManager := identityManagers.NewCookieIdentityManager(identityManagerConfig, encryptionManager, backendURI, cookieNames, 30*time.Second, cfg.HTTPTransport)
		logger.WithFields(logrus.Fields{
			"backend": backendURI,
			"signIn":  signInFormURI,
			"cookies": cookieNames,
		}).Infoln("using cookie backend identity manager")
		identityManager = cookieIdentityManager
	case "kc":
		if authorizationEndpointURI.String() != "" {
			return fmt.Errorf("kc backend is incompatible with authorization-endpoint-uri parameter")
		}
		authorizationEndpointURI.Path = "/signin/v1/identifier/_/authorize"

		if signInFormURI.EscapedPath() == "" {
			signInFormURI.Path = "/signin/v1/identifier"
		}

		identifierBackend, identifierErr := identifierBackends.NewKCIdentifierBackend(
			cfg,
			kcc.NewKCC(nil),
			os.Getenv("KOPANO_SERVER_USERNAME"),
			os.Getenv("KOPANO_SERVER_PASSWORD"),
		)
		if identifierErr != nil {
			return fmt.Errorf("failed to create identifier backend: %v", identifierErr)
		}

		activeIdentifier, err = identifier.NewIdentifier(&identifier.Config{
			Config:  cfg,
			Backend: identifierBackend,
		})
		if err != nil {
			return fmt.Errorf("failed to create identifier: %v", err)
		}
		err = activeIdentifier.SetKey(encryptionSecret)
		if err != nil {
			return fmt.Errorf("invalid --secret parameter value: %v", err)
		}

		identityManagerConfig := &identity.Config{
			SignInFormURI: signInFormURI,

			Logger: logger,
		}

		kcIdentityManager := identityManagers.NewKCIdentityManager(identityManagerConfig, activeIdentifier)
		logger.WithFields(logrus.Fields{}).Infoln("using kc backend identity manager")
		identityManager = kcIdentityManager
	case "dummy":
		dummyIdentityManager := &identityManagers.DummyIdentityManager{
			Sub: "dummy",
		}
		logger.WithField("sub", dummyIdentityManager.Sub).Warnln("using dummy identity manager")
		identityManager = dummyIdentityManager
	default:
		return fmt.Errorf("unknown identity manager %v", identityManagerName)
	}

	authorizationPath := authorizationEndpointURI.EscapedPath()
	if authorizationPath == "" {
		authorizationPath = "/konnect/v1/authorize"
	}

	activeProvider, err := provider.NewProvider(&provider.Config{
		Config: cfg,

		IssuerIdentifier:  issuerIdentifier,
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: authorizationPath,
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",

		IdentityManager: identityManager,
		CodeManager:     codeManager,
	})
	if err != nil {
		return fmt.Errorf("failed to create provider: %v", err)
	}

	listenAddr, _ := cmd.Flags().GetString("listen")
	cfg.ListenAddr = listenAddr

	srv, err := server.NewServer(&server.Config{
		Config: cfg,

		Identifier: activeIdentifier,
		Provider:   activeProvider,
	})
	if err != nil {
		return fmt.Errorf("failed to create server: %v", err)
	}

	if keyFn, _ := cmd.Flags().GetString("key"); keyFn != "" {
		signingMethodString, _ := cmd.Flags().GetString("signing-method")
		signingMethod := jwt.GetSigningMethod(signingMethodString)
		if signingMethod == nil {
			return fmt.Errorf("unknown signing method: %s", signingMethodString)
		}

		logger.WithField("file", keyFn).Infoln("loading key from file")
		err := addKeysToProvider(keyFn, activeProvider, signingMethod)
		if err != nil {
			return err
		}
		logger.WithField("alg", signingMethodString).Infoln("token signing set up")
	} else {
		//XXX(longsleep): remove me - create keypair for testing.
		key, _ := rsa.GenerateKey(rand.Reader, 512)
		activeProvider.SetSigningKey("default", key, jwt.SigningMethodRS256)
		logger.WithField("alg", jwt.SigningMethodRS256.Name).Warnln("created random RSA key pair")
	}

	logger.Infoln("serve started")
	return srv.Serve(ctx)
}

func addKeysToProvider(fn string, p *provider.Provider, signingMethod jwt.SigningMethod) error {
	fi, err := os.Stat(fn)
	if err != nil {
		return fmt.Errorf("failed load load keys: %v", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		// load all from directory.
		return fmt.Errorf("key directory not implemented")
	default:
		// file
		pemBytes, errRead := ioutil.ReadFile(fn)
		if errRead != nil {
			return fmt.Errorf("failed to parse key file: %v", errRead)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return fmt.Errorf("no PEM block found")
		}
		key, errParse := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse key: %v", errParse)
		}

		err = p.SetSigningKey("default", key, signingMethod)
	}

	return err
}
