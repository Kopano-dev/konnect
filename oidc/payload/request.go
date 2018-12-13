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

package payload

import (
	"github.com/dgrijalva/jwt-go"
)

// RequestObjectClaims holds the incoming request object claims provided as
// JWT via request parameter to OpenID Connect 1.0 authorization endpoint
// requests specified at
// https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
type RequestObjectClaims struct {
	jwt.StandardClaims

	RawScope        string         `json:"scope"`
	Claims          *ClaimsRequest `json:"claims"`
	RawResponseType string         `json:"response_type"`
	ResponseMode    string         `json:"response_mode"`
	ClientID        string         `json:"client_id"`
	RawRedirectURI  string         `json:"redirect_uri"`
	State           string         `json:"state"`
	Nonce           string         `json:"nonce"`
	RawPrompt       string         `json:"prompt"`
	RawIDTokenHint  string         `json:"id_token_hint"`
	RawMaxAge       string         `json:"max_age"`

	RawRegistration string `schema:"registration"`
}
