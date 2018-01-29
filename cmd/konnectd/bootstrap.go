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
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/encryption"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/provider"
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
	authorizationEndpointURI *url.URL

	tlsClientConfig *tls.Config

	issuerIdentifierURI  *url.URL
	identifierClientPath string

	encryptionSecret []byte
	signingMethod    jwt.SigningMethod
	signingKeyID     string
	signers          map[string]crypto.Signer
	validators       map[string]crypto.PublicKey

	cfg      *config.Config
	managers *managers
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

	authorizationEndpointURIString, _ := cmd.Flags().GetString("authorization-endpoint-uri")
	bs.authorizationEndpointURI, err = url.Parse(authorizationEndpointURIString)
	if err != nil {
		return fmt.Errorf("invalid authorization-endpoint-uri, %v", err)
	}
	if bs.authorizationEndpointURI.EscapedPath() == "" {
		bs.authorizationEndpointURI.RawPath = "/konnect/v1/authorize"
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

	if bs.signingKeyID == "" {
		bs.signingKeyID = defaultSigningKeyID
	}

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

		logger.WithField("path", signingKeyFn).Infoln("loading signing keys")
		bs.signers, bs.validators, err = loadKeys(signingKeyFn, bs.signingKeyID)
		if err != nil {
			return err
		}
	} else {
		//NOTE(longsleep): remove me - create keypair a random key pair.
		logger.WithField("alg", jwt.SigningMethodRS256.Name).Warnf("missing --signing-private-key parameter, using random %d bit signing key with signing method RS256", defaultSigningKeyBits)
		signer, _ := rsa.GenerateKey(rand.Reader, defaultSigningKeyBits)
		bs.signingMethod = jwt.SigningMethodRS256
		bs.signers = make(map[string]crypto.Signer)
		bs.validators = make(map[string]crypto.PublicKey)
		bs.signers[bs.signingKeyID] = signer
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

	return nil
}

// setup takes care of setting up the managers based on the accociated
// bootstrap's data.
func (bs *bootstrap) setup(ctx context.Context) error {
	var err error

	err = bs.setupIdentity(ctx)
	if err != nil {
		return err
	}
	err = bs.setupOIDCProvider(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (bs *bootstrap) setupIdentity(ctx context.Context) error {
	var err error
	logger := bs.cfg.Logger

	if len(bs.args) == 0 {
		return fmt.Errorf("identity-manager argument missing")
	}

	identityManagerName := bs.args[0]
	bs.managers, err = newManagers(ctx, identityManagerName, bs)
	if err != nil {
		return err
	}

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
		return err
	}
	logger.WithField("name", identityManagerName).Infoln("identity manager set up")

	bs.managers.identity = identityManager

	return nil
}

func (bs *bootstrap) setupOIDCProvider(ctx context.Context) error {
	var err error
	logger := bs.cfg.Logger

	activeProvider, err := provider.NewProvider(&provider.Config{
		Config: bs.cfg,

		IssuerIdentifier:  bs.issuerIdentifierURI.String(),
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: bs.authorizationEndpointURI.EscapedPath(),
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",

		IdentityManager: bs.managers.identity,
		CodeManager:     bs.managers.code,
	})
	if err != nil {
		return fmt.Errorf("failed to create provider: %v", err)
	}

	for id, signer := range bs.signers {
		if id == bs.signingKeyID {
			err = activeProvider.SetSigningKey(id, signer, bs.signingMethod)
		} else {
			err = activeProvider.SetValidationKey(id, signer.Public(), bs.signingMethod)
		}
		if err != nil {
			return err
		}
	}
	for id, publicKey := range bs.validators {
		err = activeProvider.SetValidationKey(id, publicKey, bs.signingMethod)
		if err != nil {
			return err
		}
	}
	logger.WithField("alg", bs.signingMethod.Alg()).Infoln("oidc token signing set up")

	bs.managers.handler = activeProvider

	logger.WithField("iss", activeProvider.Config.IssuerIdentifier).Infoln("oidc provider set up")

	return nil
}
