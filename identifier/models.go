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

package identifier

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"stash.kopano.io/kc/konnect/identifier/clients"
)

// A LogonRequest is the request data as sent to the logon endpoint
type LogonRequest struct {
	State string `json:"state"`

	Params []string      `json:"params"`
	Hello  *HelloRequest `json:"hello"`
}

// A LogonResponse holds a response as sent by the logon endpoint.
type LogonResponse struct {
	Success bool   `json:"success"`
	State   string `json:"state"`

	Hello *HelloResponse `json:"hello"`
}

// A HelloRequest is the request data as send to the hello endpoint.
type HelloRequest struct {
	State          string `json:"state"`
	Flow           string `json:"flow"`
	RawScope       string `json:"scope"`
	RawPrompt      string `json:"prompt"`
	ClientID       string `json:"client_id"`
	RawRedirectURI string `json:"redirect_uri"`
	RawIDTokenHint string `json:"id_token_hint"`
	RawMaxAge      string `json:"max_age"`

	Scopes      map[string]bool `json:"-"`
	Prompts     map[string]bool `json:"-"`
	RedirectURI *url.URL        `json:"-"`
	IDTokenHint *jwt.Token      `json:"-"`
	MaxAge      time.Duration   `json:"-"`

	//TODO(longsleep): Add support to pass request parameters as JWT as
	// specified in http://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
}

func (hr *HelloRequest) parse() error {
	hr.Scopes = make(map[string]bool)
	hr.Prompts = make(map[string]bool)

	hr.RedirectURI, _ = url.Parse(hr.RawRedirectURI)

	if hr.RawScope != "" {
		for _, scope := range strings.Split(hr.RawScope, " ") {
			hr.Scopes[scope] = true
		}
	}
	if hr.RawPrompt != "" {
		for _, prompt := range strings.Split(hr.RawPrompt, " ") {
			hr.Prompts[prompt] = true
		}
	}
	if hr.RawMaxAge != "" {
		maxAgeInt, err := strconv.ParseInt(hr.RawMaxAge, 10, 64)
		if err != nil {
			return err
		}
		hr.MaxAge = time.Duration(maxAgeInt) * time.Second
	}

	return nil
}

// A HelloResponse holds a response as sent by the hello endpoint.
type HelloResponse struct {
	State       string `json:"state"`
	Flow        string `json:"flow"`
	Success     bool   `json:"success"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"displayName,omitempty"`

	Next            string           `json:"next,omitempty"`
	ContinueURI     string           `json:"continue_uri,omitempty"`
	RequestedScopes map[string]bool  `json:"scopes,omitempty"`
	ClientDetails   *clients.Details `json:"client,omitempty"`
}

// A StateRequest is a general request with a state.
type StateRequest struct {
	State string
}

// A StateResponse hilds a response as reply to a StateRequest.
type StateResponse struct {
	Success bool   `json:"success"`
	State   string `json:"state"`
}

// A ConsentRequest is the request data as sent to the consent endpoint.
type ConsentRequest struct {
	State          string `json:"state"`
	Allow          bool   `json:"allow"`
	RawScope       string `json:"scope"`
	ClientID       string `json:"client_id"`
	RawRedirectURI string `json:"redirect_uri"`
	Ref            string `json:"ref"`
	Nonce          string `json:"flow_nonce"`
}

// Consent is the data received and sent to allow or cancel consent flows.
type Consent struct {
	Allow    bool   `json:"allow"`
	RawScope string `json:"scope"`
}

// ApprovedScopes returns the filtered list of the provied requested scopes to
// only contain accociated scopes.
func (c *Consent) ApprovedScopes(requestedScopes map[string]bool) map[string]bool {
	scopes := make(map[string]bool)
	if c.RawScope != "" {
		for _, scope := range strings.Split(c.RawScope, " ") {
			scopes[scope] = true
		}
	}

	approved := make(map[string]bool)
	for n, v := range requestedScopes {
		if ok, _ := scopes[n]; ok && v {
			approved[n] = true
		}
	}

	return approved
}
