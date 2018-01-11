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
	"crypto"
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
	identifierClients "stash.kopano.io/kc/konnect/identifier/clients"
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
	serveCmd.Flags().String("signing-private-key", "", "Full path to PEM encoded private key file (must match the --signing-method algorithm)")
	serveCmd.Flags().String("encryption-secret", "", fmt.Sprintf("Full path to a file containing a %d bytes secret key", encryption.KeySize))
	serveCmd.Flags().String("signing-method", "RS256", "JWT signing method")
	serveCmd.Flags().String("sign-in-uri", "", "Custom redirection URI to sign-in form")
	serveCmd.Flags().String("authorization-endpoint-uri", "", "Custom authorization endpoint URI")
	serveCmd.Flags().String("identifier-client-path", "./identifier/build", "Path to the identifier web client base folder")
	serveCmd.Flags().Bool("insecure", false, "Disable TLS certificate and hostname validation")
	serveCmd.Flags().StringArray("trusted-proxy", nil, "Trusted proxy IP or IP network (can be used multiple times)")

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

	trustedProxies, _ := cmd.Flags().GetStringArray("trusted-proxy")
	for _, trustedProxy := range trustedProxies {
		if ip := net.ParseIP(trustedProxy); ip != nil {
			cfg.TrustedProxyIPs = append(cfg.TrustedProxyIPs, &ip)
			continue
		}
		if _, ipNet, errParseCIDR := net.ParseCIDR(trustedProxy); errParseCIDR == nil {
			cfg.TrustedProxyNets = append(cfg.TrustedProxyNets, ipNet)
			continue
		}
	}
	if len(cfg.TrustedProxyIPs) > 0 {
		logger.Infoln("trusted proxy IPs", cfg.TrustedProxyIPs)
	}
	if len(cfg.TrustedProxyNets) > 0 {
		logger.Infoln("trusted proxy networks", cfg.TrustedProxyNets)
	}

	cfg.HTTPTransport = httpTransport

	var encryptionSecret []byte
	if encryptionSecretFilename, _ := cmd.Flags().GetString("encryption-secret"); encryptionSecretFilename != "" {
		logger.WithField("file", encryptionSecretFilename).Infoln("loading encryption secret from file")
		encryptionSecret, err = ioutil.ReadFile(encryptionSecretFilename)
		if err != nil {
			return fmt.Errorf("failed to load encryption secret from file: %v", err)
		}
		if len(encryptionSecret) != encryption.KeySize {
			return fmt.Errorf("invalid encryption secret size - must be %d bytes", encryption.KeySize)
		}
	} else {
		logger.Warnln("missing --encryption-secret parameter, using random encyption secret")
		encryptionSecret = rndm.GenerateRandomBytes(encryption.KeySize)
	}

	var encryptionManager *identityManagers.EncryptionManager
	encryptionManager, err = identityManagers.NewEncryptionManager(nil)
	if err != nil {
		return fmt.Errorf("failed to create encryption manager: %v", err)
	}
	err = encryptionManager.SetKey(encryptionSecret)
	if err != nil {
		return fmt.Errorf("invalid --encryption-secret parameter value for encryption: %v", err)
	}
	logger.Infof("encryption set up with %d key size", encryptionManager.GetKeySize())

	codeManager := codeManagers.NewMemoryMapManager(ctx)

	issuerIdentifier, _ := cmd.Flags().GetString("iss") // TODO(longsleep): Validate iss value.
	issuerIdentifierURI, _ := url.Parse(issuerIdentifier)

	identifierClientPath, _ := cmd.Flags().GetString("identifier-client-path")

	clientRegistry, _ := identifierClients.NewRegistry(issuerIdentifierURI, logger)

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
		}).Infoln("using cookie backed identity manager")
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

		fullAuthorizationEndpointURL, _ := url.Parse(issuerIdentifierURI.String())
		fullAuthorizationEndpointURL.Path = authorizationEndpointURI.Path

		activeIdentifier, err = identifier.NewIdentifier(&identifier.Config{
			Config: cfg,

			PathPrefix:      "/signin/v1",
			StaticFolder:    identifierClientPath,
			LogonCookieName: "__Secure-KKT", // Kopano-Konnect-Token

			AuthorizationEndpointURI: fullAuthorizationEndpointURL,

			Backend: identifierBackend,
			Clients: clientRegistry,
		})
		if err != nil {
			return fmt.Errorf("failed to create identifier: %v", err)
		}
		err = activeIdentifier.SetKey(encryptionSecret)
		if err != nil {
			return fmt.Errorf("invalid --encryption-secret parameter value for identifier: %v", err)
		}

		identityManagerConfig := &identity.Config{
			SignInFormURI: signInFormURI,

			Logger: logger,
		}

		identifierIdentityManager := identityManagers.NewIdentifierIdentityManager(identityManagerConfig, activeIdentifier, clientRegistry)
		logger.WithFields(logrus.Fields{}).Infoln("using identifier backed identity manager")
		identityManager = identifierIdentityManager
	case "ldap":
		if authorizationEndpointURI.String() != "" {
			return fmt.Errorf("ldap backend is incompatible with authorization-endpoint-uri parameter")
		}
		authorizationEndpointURI.Path = "/signin/v1/identifier/_/authorize"

		if signInFormURI.EscapedPath() == "" {
			signInFormURI.Path = "/signin/v1/identifier"
		}

		identifierBackend, identifierErr := identifierBackends.NewLDAPIdentifierBackend(
			cfg,
			httpTransport.TLSClientConfig,
			os.Getenv("LDAP_URI"),
			os.Getenv("LDAP_BINDDN"),
			os.Getenv("LDAP_BINDPW"),
			os.Getenv("LDAP_BASEDN"),
			os.Getenv("LDAP_SCOPE"),
			os.Getenv("LDAP_LOGIN_ATTRIBUTE"),
			os.Getenv("LDAP_EMAIL_ATTRIBUTE"),
			os.Getenv("LDAP_NAME_ATTRIBUTE"),
			os.Getenv("LDAP_FILTER"),
		)
		if identifierErr != nil {
			return fmt.Errorf("failed to create identifier backend: %v", identifierErr)
		}

		fullAuthorizationEndpointURL, _ := url.Parse(issuerIdentifierURI.String())
		fullAuthorizationEndpointURL.Path = authorizationEndpointURI.Path

		activeIdentifier, err = identifier.NewIdentifier(&identifier.Config{
			Config: cfg,

			PathPrefix:      "/signin/v1",
			StaticFolder:    identifierClientPath,
			LogonCookieName: "__Secure-KKT", // Kopano-Konnect-Token

			AuthorizationEndpointURI: fullAuthorizationEndpointURL,

			Backend: identifierBackend,
			Clients: clientRegistry,
		})
		if err != nil {
			return fmt.Errorf("failed to create identifier: %v", err)
		}
		err = activeIdentifier.SetKey(encryptionSecret)
		if err != nil {
			return fmt.Errorf("invalid --encryption-secret parameter value for identifier: %v", err)
		}

		identityManagerConfig := &identity.Config{
			SignInFormURI: signInFormURI,

			Logger: logger,
		}

		identifierIdentityManager := identityManagers.NewIdentifierIdentityManager(identityManagerConfig, activeIdentifier, clientRegistry)
		logger.WithFields(logrus.Fields{}).Infoln("using identifier backed identity manager")
		identityManager = identifierIdentityManager
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

	if signingKeyFn, _ := cmd.Flags().GetString("signing-private-key"); signingKeyFn != "" {
		signingMethodString, _ := cmd.Flags().GetString("signing-method")
		signingMethod := jwt.GetSigningMethod(signingMethodString)
		if signingMethod == nil {
			return fmt.Errorf("unknown signing method: %s", signingMethodString)
		}

		logger.WithField("file", signingKeyFn).Infoln("loading signing key from file")
		err := addKeysToProvider(signingKeyFn, activeProvider, signingMethod)
		if err != nil {
			return err
		}
		logger.WithField("alg", signingMethodString).Infoln("token signing set up")
	} else {
		//NOTE(longsleep): remove me - create keypair a random key pair.
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		logger.WithField("alg", jwt.SigningMethodRS256.Name).Warnln("created random signing key with signing method RS256")
		activeProvider.SetSigningKey("default", key, jwt.SigningMethodRS256)
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

		var signer crypto.Signer
		for {
			pkcs1Key, errParse1 := x509.ParsePKCS1PrivateKey(block.Bytes)
			if errParse1 == nil {
				signer = pkcs1Key
				break
			}

			pkcs8Key, errParse2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if errParse2 == nil {
				signerSigner, ok := pkcs8Key.(crypto.Signer)
				if !ok {
					return fmt.Errorf("failed to use key as crypto signer")
				}
				signer = signerSigner
				break
			}

			return fmt.Errorf("failed to parse key - valid PKCS#1 or PKCS#8? %v, %v", errParse1, errParse2)
		}

		err = p.SetSigningKey("default", signer, signingMethod)
	}

	return err
}
