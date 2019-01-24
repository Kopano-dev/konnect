/*
 * Copyright 2018 Kopano and its licensors
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
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/encryption"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/managers"
	oidcProvider "stash.kopano.io/kc/konnect/oidc/provider"
)

// Identity managers.
const (
	identityManagerNameCookie = "cookie"
	identityManagerNameDummy  = "dummy"
	identityManagerNameKC     = "kc"
	identityManagerNameLDAP   = "ldap"
)

// bootstrap is a data structure to hold configuration required to start
// konnectd.
type bootstrap struct {
	cmd  *cobra.Command
	args []string

	signInFormURI            *url.URL
	signedOutURI             *url.URL
	authorizationEndpointURI *url.URL
	endSessionEndpointURI    *url.URL

	tlsClientConfig *tls.Config

	issuerIdentifierURI        *url.URL
	identifierClientPath       string
	identifierRegistrationConf string
	identifierScopesConf       string

	encryptionSecret []byte
	signingMethod    jwt.SigningMethod
	signingKeyID     string
	signers          map[string]crypto.Signer
	validators       map[string]crypto.PublicKey

	accessTokenDurationSeconds uint64

	cfg      *config.Config
	managers *managers.Managers
}

// initialize, parsed parameters from commandline with validation and adds them
// to the accociated bootstrap data.
func (bs *bootstrap) initialize() error {
	cmd := bs.cmd
	logger := bs.cfg.Logger
	var err error

	if len(bs.args) == 0 {
		return fmt.Errorf("identity-manager argument missing, use one of kc, ldap, cookie, dummy")
	}

	issuerIdentifier, _ := cmd.Flags().GetString("iss")
	bs.issuerIdentifierURI, err = url.Parse(issuerIdentifier)
	if err != nil {
		return fmt.Errorf("invalid iss value, iss is not a valid URL), %v", err)
	} else if issuerIdentifier == "" {
		return fmt.Errorf("missing iss value, did you provide the --iss parameter?")
	} else if bs.issuerIdentifierURI.Scheme != "https" {
		return fmt.Errorf("invalid iss value, URL must start with https://")
	} else if bs.issuerIdentifierURI.Host == "" {
		return fmt.Errorf("invalid iss value, URL must have a host")
	}

	signInFormURIString, _ := cmd.Flags().GetString("sign-in-uri")
	bs.signInFormURI, err = url.Parse(signInFormURIString)
	if err != nil {
		return fmt.Errorf("invalid sign-in URI, %v", err)
	}

	signedOutURIString, _ := cmd.Flags().GetString("signed-out-uri")
	bs.signedOutURI, err = url.Parse(signedOutURIString)
	if err != nil {
		return fmt.Errorf("invalid signed-out URI, %v", err)
	}

	authorizationEndpointURIString, _ := cmd.Flags().GetString("authorization-endpoint-uri")
	bs.authorizationEndpointURI, err = url.Parse(authorizationEndpointURIString)
	if err != nil {
		return fmt.Errorf("invalid authorization-endpoint-uri, %v", err)
	}

	endSessionEndpointURIString, _ := cmd.Flags().GetString("endsession-endpoint-uri")
	bs.endSessionEndpointURI, err = url.Parse(endSessionEndpointURIString)
	if err != nil {
		return fmt.Errorf("invalid endsession-endpoint-uri, %v", err)
	}

	tlsInsecureSkipVerify, _ := cmd.Flags().GetBool("insecure")
	if tlsInsecureSkipVerify {
		// NOTE(longsleep): This disable http2 client support. See https://github.com/golang/go/issues/14275 for reasons.
		bs.tlsClientConfig = &tls.Config{
			InsecureSkipVerify: tlsInsecureSkipVerify,
		}
		logger.Warnln("insecure mode, TLS client connections are susceptible to man-in-the-middle attacks")
		logger.Debugln("http2 client support is disabled (insecure mode)")
	}

	trustedProxies, _ := cmd.Flags().GetStringArray("trusted-proxy")
	for _, trustedProxy := range trustedProxies {
		if ip := net.ParseIP(trustedProxy); ip != nil {
			bs.cfg.TrustedProxyIPs = append(bs.cfg.TrustedProxyIPs, &ip)
			continue
		}
		if _, ipNet, errParseCIDR := net.ParseCIDR(trustedProxy); errParseCIDR == nil {
			bs.cfg.TrustedProxyNets = append(bs.cfg.TrustedProxyNets, ipNet)
			continue
		}
	}
	if len(bs.cfg.TrustedProxyIPs) > 0 {
		logger.Infoln("trusted proxy IPs", bs.cfg.TrustedProxyIPs)
	}
	if len(bs.cfg.TrustedProxyNets) > 0 {
		logger.Infoln("trusted proxy networks", bs.cfg.TrustedProxyNets)
	}

	allowedScopes, _ := cmd.Flags().GetStringArray("allow-scope")
	if len(allowedScopes) > 0 {
		bs.cfg.AllowedScopes = allowedScopes
		logger.Infoln("using custom allowed OAuth 2 scopes", bs.cfg.AllowedScopes)
	}

	bs.cfg.AllowClientGuests, _ = cmd.Flags().GetBool("allow-client-guests")
	if bs.cfg.AllowClientGuests {
		logger.Infoln("client controlled guests are enabled")
	}

	encryptionSecretFn, _ := cmd.Flags().GetString("encryption-secret")
	if encryptionSecretFn == "" {
		encryptionSecretFn = os.Getenv("KONNECTD_ENCRYPTION_SECRET")
	}
	if encryptionSecretFn != "" {
		logger.WithField("file", encryptionSecretFn).Infoln("loading encryption secret from file")
		bs.encryptionSecret, err = ioutil.ReadFile(encryptionSecretFn)
		if err != nil {
			return fmt.Errorf("failed to load encryption secret from file: %v", err)
		}
		if len(bs.encryptionSecret) != encryption.KeySize {
			return fmt.Errorf("invalid encryption secret size - must be %d bytes", encryption.KeySize)
		}
	} else {
		logger.Warnf("missing --encryption-secret parameter, using random encyption secret with %d bytes", encryption.KeySize)
		bs.encryptionSecret = rndm.GenerateRandomBytes(encryption.KeySize)
	}

	bs.cfg.ListenAddr, _ = cmd.Flags().GetString("listen")
	if bs.cfg.ListenAddr == "" {
		bs.cfg.ListenAddr = os.Getenv("KONNECTD_LISTEN")
	}
	if bs.cfg.ListenAddr == "" {
		bs.cfg.ListenAddr = defaultListenAddr
	}

	bs.identifierClientPath, _ = cmd.Flags().GetString("identifier-client-path")
	if bs.identifierClientPath == "" {
		bs.identifierClientPath = os.Getenv("KONNECTD_IDENTIFIER_CLIENT_PATH")
	}
	if bs.identifierClientPath == "" {
		bs.identifierClientPath = defaultIdentifierClientPath
	}

	bs.identifierRegistrationConf, _ = cmd.Flags().GetString("identifier-registration-conf")
	if bs.identifierRegistrationConf != "" {
		bs.identifierRegistrationConf, _ = filepath.Abs(bs.identifierRegistrationConf)
		if _, errStat := os.Stat(bs.identifierRegistrationConf); errStat != nil {
			return fmt.Errorf("identifier-registration-conf file not found or unable to access: %v", errStat)
		}
	}

	bs.identifierScopesConf, _ = cmd.Flags().GetString("identifier-scopes-conf")
	if bs.identifierScopesConf != "" {
		bs.identifierScopesConf, _ = filepath.Abs(bs.identifierScopesConf)
		if _, errStat := os.Stat(bs.identifierScopesConf); errStat != nil {
			return fmt.Errorf("identifier-scopes-conf file not found or unable to access: %v", errStat)
		}
	}

	bs.signingKeyID, _ = cmd.Flags().GetString("signing-kid")
	if bs.signingKeyID == "" {
		bs.signingKeyID = os.Getenv("KONNECTD_SIGNING_KID")
	}

	bs.signers = make(map[string]crypto.Signer)
	bs.validators = make(map[string]crypto.PublicKey)

	signingKeyFn, _ := cmd.Flags().GetString("signing-private-key")
	if signingKeyFn == "" {
		signingKeyFn = os.Getenv("KONNECTD_SIGNING_PRIVATE_KEY")
	}
	if signingKeyFn != "" {
		signingMethodString, _ := cmd.Flags().GetString("signing-method")
		bs.signingMethod = jwt.GetSigningMethod(signingMethodString)
		if bs.signingMethod == nil {
			return fmt.Errorf("unknown signing method: %s", signingMethodString)
		}
		if signingMethodRSAPSS, ok := bs.signingMethod.(*jwt.SigningMethodRSAPSS); ok {
			// NOTE(longsleep): Ensure to use same salt length the hash size.
			// See https://www.ietf.org/mail-archive/web/jose/current/msg02901.html for
			// reference and https://github.com/dgrijalva/jwt-go/issues/285 for
			// the issue in upstream jwt-go.
			signingMethodRSAPSS.Options.SaltLength = rsa.PSSSaltLengthEqualsHash
		}

		logger.WithField("path", signingKeyFn).Infoln("loading signing key")
		err = addSignerWithIDFromFile(signingKeyFn, bs.signingKeyID, bs)
		if err != nil {
			return err
		}
	} else {
		//NOTE(longsleep): remove me - create keypair a random key pair.
		sm := jwt.SigningMethodPS256
		bs.signingMethod = sm
		logger.WithField("alg", sm.Name).Warnf("missing --signing-private-key parameter, using random %d bit signing key", defaultSigningKeyBits)
		signer, _ := rsa.GenerateKey(rand.Reader, defaultSigningKeyBits)
		bs.signers[bs.signingKeyID] = signer
	}

	validationKeysPath, _ := cmd.Flags().GetString("validation-keys-path")
	if validationKeysPath == "" {
		validationKeysPath = os.Getenv("KONNECTD_VALIDATION_KEYS_PATH")
	}
	if validationKeysPath != "" {
		logger.WithField("path", validationKeysPath).Infoln("loading validation keys")
		err = addValidatorsFromPath(validationKeysPath, bs)
		if err != nil {
			return err
		}
	}

	bs.cfg.HTTPTransport = &http.Transport{
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
		TLSClientConfig:       bs.tlsClientConfig,
	}

	bs.accessTokenDurationSeconds = 10 * 60 // 10 Minutes.

	return nil
}

// setup takes care of setting up the managers based on the accociated
// bootstrap's data.
func (bs *bootstrap) setup(ctx context.Context) error {
	managers, err := newManagers(ctx, bs)
	if err != nil {
		return err
	}

	identityManager, err := bs.setupIdentity(ctx)
	if err != nil {
		return err
	}
	managers.Set("identity", identityManager)

	guestManager, err := bs.setupGuest(ctx, identityManager)
	if err != nil {
		return err
	}
	managers.Set("guest", guestManager)

	oidcProvider, err := bs.setupOIDCProvider(ctx)
	if err != nil {
		return err
	}
	managers.Set("oidc", oidcProvider)
	managers.Set("handler", oidcProvider) // Use OIDC provider as default HTTP handler.

	err = managers.Apply()
	if err != nil {
		return fmt.Errorf("failed to apply managers: %v", err)
	}

	// Final steps
	err = oidcProvider.InitializeMetadata()
	if err != nil {
		return fmt.Errorf("failed to initialize provider metadata: %v", err)
	}

	bs.managers = managers
	return nil
}

func (bs *bootstrap) setupIdentity(ctx context.Context) (identity.Manager, error) {
	var err error
	logger := bs.cfg.Logger

	if len(bs.args) == 0 {
		return nil, fmt.Errorf("identity-manager argument missing")
	}

	identityManagerName := bs.args[0]

	// Identity manager.
	var identityManager identity.Manager
	switch identityManagerName {
	case identityManagerNameCookie:
		identityManager, err = newCookieIdentityManager(bs)

	case identityManagerNameKC:
		identityManager, err = newKCIdentityManager(bs)

	case identityManagerNameLDAP:
		identityManager, err = newLDAPIdentityManager(bs)

	case identityManagerNameDummy:
		identityManager, err = newDummyIdentityManager(bs)

	default:
		err = fmt.Errorf("unknown identity manager %v", identityManagerName)
	}
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{
		"name":   identityManagerName,
		"scopes": identityManager.ScopesSupported(nil),
		"claims": identityManager.ClaimsSupported(nil),
	}).Infoln("identity manager set up")

	return identityManager, nil
}

func (bs *bootstrap) setupGuest(ctx context.Context, identityManager identity.Manager) (identity.Manager, error) {
	if !bs.cfg.AllowClientGuests {
		return nil, nil
	}

	var err error
	logger := bs.cfg.Logger

	guestManager, err := newGuestIdentityManager(bs)
	if err != nil {
		return nil, err
	}

	if guestManager != nil {
		logger.Infoln("identity guest manager set up")
	}
	return guestManager, nil
}

func (bs *bootstrap) setupOIDCProvider(ctx context.Context) (*oidcProvider.Provider, error) {
	var err error
	logger := bs.cfg.Logger

	sessionCookiePath, err := getCommonURLPathPrefix(bs.authorizationEndpointURI.EscapedPath(), bs.endSessionEndpointURI.EscapedPath())
	if err != nil {
		return nil, fmt.Errorf("failed to find common URL prefix for authorize and endsession: %v", err)
	}

	provider, err := oidcProvider.NewProvider(&oidcProvider.Config{
		Config: bs.cfg,

		IssuerIdentifier:       bs.issuerIdentifierURI.String(),
		WellKnownPath:          "/.well-known/openid-configuration",
		JwksPath:               "/konnect/v1/jwks.json",
		AuthorizationPath:      bs.authorizationEndpointURI.EscapedPath(),
		TokenPath:              "/konnect/v1/token",
		UserInfoPath:           "/konnect/v1/userinfo",
		EndSessionPath:         bs.endSessionEndpointURI.EscapedPath(),
		CheckSessionIframePath: "/konnect/v1/session/check-session.html",

		BrowserStateCookiePath: "/konnect/v1/session/",
		BrowserStateCookieName: "__Secure-KKBS", // Kopano-Konnect-Browser-State

		SessionCookiePath: sessionCookiePath,
		SessionCookieName: "__Secure-KKCS", // Kopano-Konnect-Client-Session

		AccessTokenDuration:  time.Duration(bs.accessTokenDurationSeconds) * time.Second,
		IDTokenDuration:      1 * time.Hour,            // 1 Hour, must be consumed by then.
		RefreshTokenDuration: 24 * 365 * 3 * time.Hour, // 3 Years.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}

	for id, signer := range bs.signers {
		if id == bs.signingKeyID {
			err = provider.SetSigningKey(id, signer, bs.signingMethod)
			// Always set default key.
			if id != defaultSigningKeyID {
				provider.SetValidationKey(defaultSigningKeyID, signer.Public(), bs.signingMethod)
			}
		} else {
			err = provider.SetValidationKey(id, signer.Public(), bs.signingMethod)
		}
		if err != nil {
			return nil, err
		}
	}
	for id, publicKey := range bs.validators {
		err = provider.SetValidationKey(id, publicKey, bs.signingMethod)
		if err != nil {
			return nil, err
		}
	}
	logger.Infoln("oidc token signing set up")

	return provider, nil
}
