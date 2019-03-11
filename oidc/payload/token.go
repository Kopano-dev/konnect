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

package payload

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"stash.kopano.io/kc/konnect/oidc"
)

// TokenRequest holds the incoming parameters and request data for
// the OpenID Connect 1.0 token endpoint as specified at
// http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
type TokenRequest struct {
	providerMetadata *WellKnown

	GrantType       string `schema:"grant_type"`
	Code            string `schema:"code"`
	RawRedirectURI  string `schema:"redirect_uri"`
	RawRefreshToken string `schema:"refresh_token"`
	RawScope        string `schema:"scope"`

	ClientID     string `schema:"client_id"`
	ClientSecret string `schema:"client_secret"`

	CodeVerifier string `schema:"code_verifier"`

	RedirectURI  *url.URL        `schema:"-"`
	RefreshToken *jwt.Token      `schema:"-"`
	Scopes       map[string]bool `schema:"-"`
}

// DecodeTokenRequest return a TokenRequest holding the provided
// request's form data.
func DecodeTokenRequest(req *http.Request, providerMetadata *WellKnown) (*TokenRequest, error) {
	tr, err := NewTokenRequest(req.PostForm, providerMetadata)
	if err != nil {
		return nil, err
	}

	auth := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	switch auth[0] {
	case "Basic":
		if len(auth) != 2 {
			return nil, fmt.Errorf("invalid Basic authorization header format")
		}
		var basic []byte
		if basic, err = base64.StdEncoding.DecodeString(auth[1]); err != nil {
			return nil, err
		}
		// Split client id and secret.
		check := strings.SplitN(string(basic), ":", 2)
		// Data is encoded application/x-www-form-urlencoded UTF-8. See
		// https://tools.ietf.org/html/rfc6749#appendix-B for details.
		tr.ClientID, err = url.QueryUnescape(check[0])
		if err != nil {
			return nil, err
		}
		tr.ClientSecret, err = url.QueryUnescape(check[1])
		if err != nil {
			return nil, err
		}
	}

	return tr, err
}

// NewTokenRequest returns a TokenRequest holding the provided url values.
func NewTokenRequest(values url.Values, providerMetadata *WellKnown) (*TokenRequest, error) {
	tr := &TokenRequest{
		providerMetadata: providerMetadata,

		Scopes: make(map[string]bool),
	}

	err := DecodeSchema(tr, values)
	if err != nil {
		return nil, err
	}

	tr.RedirectURI, _ = url.Parse(tr.RawRedirectURI)

	if tr.RawScope != "" {
		for _, scope := range strings.Split(tr.RawScope, " ") {
			tr.Scopes[scope] = true
		}
	}

	return tr, nil
}

// Validate validates the request data of the accociated token request.
func (tr *TokenRequest) Validate(keyFunc jwt.Keyfunc, claims jwt.Claims) error {
	switch tr.GrantType {
	case oidc.GrantTypeAuthorizationCode:
		// breaks
	case oidc.GrantTypeRefreshToken:
		if tr.RawRefreshToken != "" {
			refreshToken, err := jwt.ParseWithClaims(tr.RawRefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
				if keyFunc != nil {
					return keyFunc(token)
				}

				return nil, fmt.Errorf("Not validated")
			})
			if err != nil {
				return oidc.NewOAuth2Error(oidc.ErrorOAuth2InvalidRequest, err.Error())
			}
			tr.RefreshToken = refreshToken
		}
		// breaks

	default:
		return oidc.NewOAuth2Error(oidc.ErrorOAuth2UnsupportedGrantType, "unsupported grant_type value")
	}

	return nil
}

// TokenSuccess holds the outgoing data for a successful OpenID
// Connect 1.0 token request as specified at
// http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse.
type TokenSuccess struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
}
