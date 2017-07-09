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
	"time"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/code"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
)

// Provider defines an OIDC provider with the handlers for the OIDC endpoints.
type Provider struct {
	issuerIdentifier string

	wellKnownPath     string
	jwksPath          string
	authorizationPath string
	tokenPath         string
	userInfoPath      string

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
		issuerIdentifier:  c.IssuerIdentifier,
		wellKnownPath:     c.WellKnownPath,
		jwksPath:          c.JwksPath,
		authorizationPath: c.AuthorizationPath,
		tokenPath:         c.TokenPath,
		userInfoPath:      c.UserInfoPath,

		identityManager: c.IdentityManager,
		codeManager:     c.CodeManager,

		validationKeys: make(map[string]crypto.PublicKey),

		accessTokenDuration: time.Minute * 10, //TODO(longsleep): Move to configuration.

		logger: c.Logger,
	}

	return p, nil
}

func (p *Provider) makeIssURL(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf("%s%s", p.issuerIdentifier, path)
}

// SetSigningKey sets the provided signer as key for token signing and uses the provided id as key id. The public key of the provided
// signer is also added as validation key with the same id.
func (p *Provider) SetSigningKey(id string, key crypto.Signer, signingMethod jwt.SigningMethod) error {
	p.validationKeys[id] = key.Public()
	p.signingKey = key
	p.signingKeyID = id
	p.signingMethod = signingMethod

	return nil
}

// ServerHTTP implements the http.HandlerFunc interface.
func (p *Provider) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch path := req.URL.Path; {
	case path == p.wellKnownPath:
		p.WellKnownHandler(rw, req)
	case path == p.jwksPath:
		http.NotFound(rw, req)
	case path == p.authorizationPath:
		p.AuthorizeHandler(rw, req)
	case path == p.tokenPath:
		http.NotFound(rw, req)
	case path == p.userInfoPath:
		http.NotFound(rw, req)
	default:
		http.NotFound(rw, req)
	}
}

// ErrorPage writes a HTML error page to the provided ResponseWriter.
func (p *Provider) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	if title == "" {
		title = http.StatusText(code)
	}

	http.Error(rw, fmt.Sprintf("%d %s - %s", code, title, message), code)
}

// Found writes a HTTP 302 to the provided ResponseWriter with the appropriate
// Location header creates from the other parameters.
func (p *Provider) Found(rw http.ResponseWriter, uri *url.URL, params interface{}, asFragment bool) {
	err := redirect(rw, http.StatusFound, uri, params, asFragment)
	if err != nil {
		p.ErrorPage(rw, http.StatusInternalServerError, "", err.Error())
	}
}
