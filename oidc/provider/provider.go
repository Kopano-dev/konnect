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

package provider

import (
	"crypto"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/code"
	"stash.kopano.io/kc/konnect/utils"
)

// Provider defines an OIDC provider with the handlers for the OIDC endpoints.
type Provider struct {
	Config *Config

	issuerIdentifier string

	wellKnownPath     string
	jwksPath          string
	authorizationPath string
	tokenPath         string
	userInfoPath      string
	endSessionPath    string

	identityManager identity.Manager
	codeManager     code.Manager

	signingMethod  jwt.SigningMethod
	signingKey     crypto.PrivateKey
	signingKeyID   string
	validationKeys map[string]crypto.PublicKey

	accessTokenDuration time.Duration

	logger logrus.FieldLogger
}

// NewProvider returns a new Provider.
func NewProvider(c *Config) (*Provider, error) {
	p := &Provider{
		Config: c,

		issuerIdentifier:  c.IssuerIdentifier,
		wellKnownPath:     c.WellKnownPath,
		jwksPath:          c.JwksPath,
		authorizationPath: c.AuthorizationPath,
		tokenPath:         c.TokenPath,
		userInfoPath:      c.UserInfoPath,
		endSessionPath:    c.EndSessionPath,

		identityManager: c.IdentityManager,
		codeManager:     c.CodeManager,

		validationKeys: make(map[string]crypto.PublicKey),

		accessTokenDuration: time.Minute * 10, //TODO(longsleep): Move to configuration.

		logger: c.Config.Logger,
	}

	return p, nil
}

func (p *Provider) makeIssURL(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("%s%s", p.issuerIdentifier, path)
}

// SetSigningKey sets the provided signer as key for token signing and uses the
// provided id as key id. The public key of the provided signer is also added as
// validation key with the same id.
func (p *Provider) SetSigningKey(id string, key crypto.Signer, signingMethod jwt.SigningMethod) error {
	p.logger.WithFields(logrus.Fields{
		"type": fmt.Sprintf("%T", key),
		"id":   id,
	}).Infoln("set provider signing key")

	p.signingKey = key
	p.signingKeyID = id
	p.signingMethod = signingMethod

	p.SetValidationKey(id, key.Public(), signingMethod)

	return nil
}

// SetValidationKey sets the provider public key as validation key for token
// validation for tokens with the provided key.
func (p *Provider) SetValidationKey(id string, key crypto.PublicKey, signingMethod jwt.SigningMethod) error {
	if p.signingMethod != signingMethod {
		return fmt.Errorf("signing method mismatch")
	}

	p.logger.WithFields(logrus.Fields{
		"type": fmt.Sprintf("%T", key),
		"id":   id,
	}).Infoln("set provider validation key")

	p.validationKeys[id] = key

	return nil
}

// ServerHTTP implements the http.HandlerFunc interface.
func (p *Provider) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch path := req.URL.Path; {
	case path == p.wellKnownPath:
		cors.Default().ServeHTTP(rw, req, p.WellKnownHandler)
	case path == p.jwksPath:
		cors.Default().ServeHTTP(rw, req, p.JwksHandler)
	case path == p.authorizationPath:
		p.AuthorizeHandler(rw, req)
	case path == p.tokenPath:
		cors.Default().ServeHTTP(rw, req, p.TokenHandler)
	case path == p.userInfoPath:
		// TODO(longsleep): Use more strict CORS.
		cors.AllowAll().ServeHTTP(rw, req, p.UserInfoHandler)
	case path == p.endSessionPath:
		p.EndSessionHandler(rw, req)
	default:
		http.NotFound(rw, req)
	}
}

// ErrorPage writes a HTML error page to the provided ResponseWriter.
func (p *Provider) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	utils.WriteErrorPage(rw, code, title, message)
}

// Found writes a HTTP 302 to the provided ResponseWriter with the appropriate
// Location header creates from the other parameters.
func (p *Provider) Found(rw http.ResponseWriter, uri *url.URL, params interface{}, asFragment bool) {
	err := utils.WriteRedirect(rw, http.StatusFound, uri, params, asFragment)
	if err != nil {
		p.logger.WithError(err).Debugln("failed to write to response")
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
		return
	}
}

// LoginRequiredPage writes a HTTP 30 to the provided ResponseWrite with the
// URL of the provided request (set to the scheme and host of issuer) as
// continue parameter.
func (p *Provider) LoginRequiredPage(rw http.ResponseWriter, req *http.Request, uri *url.URL) {
	issURI, _ := url.Parse(p.issuerIdentifier)

	trusted, _ := utils.IsRequestFromTrustedSource(req, p.Config.Config.TrustedProxyIPs, p.Config.Config.TrustedProxyNets)

	continueURI := getRequestURL(req, trusted)
	continueURI.Scheme = issURI.Scheme
	continueURI.Host = issURI.Host

	uri, err := url.Parse(fmt.Sprintf("%s?continue=%s&oauth=1", uri.String(), url.QueryEscape(continueURI.String())))
	if err != nil {
		p.logger.WithError(err).Debugln("failed to parse sign-in URL")
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
		return
	}

	p.Found(rw, uri, nil, false)
}

// GetAccessTokenClaimsFromRequest reads incoming request, validates the
// access token and returns the validated claims.
func (p *Provider) GetAccessTokenClaimsFromRequest(req *http.Request) (*konnect.AccessTokenClaims, error) {
	var err error
	var claims *konnect.AccessTokenClaims

	auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	switch auth[0] {
	case oidc.TokenTypeBearer:
		if len(auth) != 2 {
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, "Invalid Bearer authorization header format")
			break
		}
		claims = &konnect.AccessTokenClaims{}
		_, err = jwt.ParseWithClaims(auth[1], claims, func(token *jwt.Token) (interface{}, error) {
			// Validator for incoming access tokens, looks up key.
			return p.validateJWT(token)
		})
		if err != nil {
			// Wrap as OAuth2 error.
			err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidToken, err.Error())
		}

	default:
		err = oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, "Bearer authorization required")
	}

	return claims, err
}
