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

package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/crypto/blake2b"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

var browserStateMarker = []byte("kopano-konnect-1")

func (p *Provider) makeBrowserState(ar *payload.AuthenticationRequest, auth identity.AuthRecord, err error) (string, error) {
	hasher, hasherErr := blake2b.New256(nil)
	if hasherErr != nil {
		return "", hasherErr
	}
	if auth != nil && err == nil {
		hasher.Write([]byte(auth.Subject()))
	} else {
		// Use empty string value when not signed in or with error. This means
		// that a browser state is always created.
		hasher.Write([]byte(" "))
	}
	hasher.Write([]byte(" "))
	hasher.Write([]byte(p.issuerIdentifier))
	hasher.Write([]byte(" "))
	hasher.Write(browserStateMarker)

	// Encode to string.
	browserState := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return browserState, nil
}

func (p *Provider) makeSessionState(req *http.Request, ar *payload.AuthenticationRequest, browserState string) (string, error) {
	var origin string

	for {
		redirectURL := ar.RedirectURI
		if redirectURL != nil {
			origin = fmt.Sprintf("%s://%s", redirectURL.Scheme, redirectURL.Host)
			break
		}

		originHeader := req.Header.Get("Origin")
		if originHeader != "" {
			origin = originHeader
			break
		}

		refererHeader := req.Header.Get("Referer")
		if refererHeader != "" {
			// Rescure from referer.
			refererURL, err := url.Parse(refererHeader)
			if err != nil {
				return "", fmt.Errorf("invalid referer value: %v", err)
			}

			origin = fmt.Sprintf("%s://%s", refererURL.Scheme, refererURL.Host)
			break
		}

		return "", fmt.Errorf("missing origin")
	}

	salt := rndm.GenerateRandomString(32)

	hasher := sha256.New()
	hasher.Write([]byte(ar.ClientID))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(origin))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(browserState))
	hasher.Write([]byte(" "))
	hasher.Write([]byte(salt))

	sessionState := fmt.Sprintf("%s.%s", hex.EncodeToString(hasher.Sum(nil)), salt)

	return sessionState, nil
}
