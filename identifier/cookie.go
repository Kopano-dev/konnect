/*
 * Copyright 2017-2019 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package identifier

import (
	"encoding/base64"
	"net/http"

	"golang.org/x/crypto/blake2b"
)

func (i *Identifier) setLogonCookie(rw http.ResponseWriter, value string) error {
	cookie := http.Cookie{
		Name:  i.logonCookieName,
		Value: value,

		Path:     i.pathPrefix + "/identifier/_/",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) getLogonCookie(req *http.Request) (*http.Cookie, error) {
	return req.Cookie(i.logonCookieName)
}

func (i *Identifier) removeLogonCookie(rw http.ResponseWriter) error {
	cookie := http.Cookie{
		Name: i.logonCookieName,

		Path:     i.pathPrefix + "/identifier/_/",
		Secure:   true,
		HttpOnly: true,

		Expires: farPastExpiryTime,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) setConsentCookie(rw http.ResponseWriter, cr *ConsentRequest, value string) error {
	name, err := i.getConsentCookieName(cr)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: 60,

		Path:     i.pathPrefix + "/identifier/_/",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) getConsentCookie(req *http.Request, cr *ConsentRequest) (*http.Cookie, error) {
	name, err := i.getConsentCookieName(cr)
	if err != nil {
		return nil, err
	}

	return req.Cookie(name)
}

func (i *Identifier) removeConsentCookie(rw http.ResponseWriter, req *http.Request, cr *ConsentRequest) error {
	name, err := i.getConsentCookieName(cr)
	if err != nil {
		return nil
	}

	cookie := http.Cookie{
		Name: name,

		Path:     i.pathPrefix + "/identifier/_/",
		Secure:   true,
		HttpOnly: true,

		Expires: farPastExpiryTime,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) getConsentCookieName(cr *ConsentRequest) (string, error) {
	// Consent cookie names are based on parameters in the request.
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return "", err
	}

	hasher.Write([]byte(cr.State))
	hasher.Write([]byte("h"))
	hasher.Write([]byte(cr.ClientID))
	hasher.Write([]byte("e"))
	hasher.Write([]byte(cr.RawRedirectURI))
	hasher.Write([]byte("l"))
	hasher.Write([]byte(cr.Ref))
	hasher.Write([]byte("o"))
	hasher.Write([]byte(cr.Nonce))

	name := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return name, nil
}

func (i *Identifier) setOAuth2Cookie(rw http.ResponseWriter, state string, value string) error {
	name, err := i.getOAuth2CookieName(state)
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: 60,

		Path:     i.pathPrefix + "/identifier/oauth2/cb",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) getOAuth2Cookie(req *http.Request, state string) (*http.Cookie, error) {
	name, err := i.getOAuth2CookieName(state)
	if err != nil {
		return nil, err
	}

	return req.Cookie(name)
}

func (i *Identifier) removeOAuth2Cookie(rw http.ResponseWriter, req *http.Request, state string) error {
	name, err := i.getOAuth2CookieName(state)
	if err != nil {
		return nil
	}

	cookie := http.Cookie{
		Name: name,

		Path:     i.pathPrefix + "/identifier/oauth2/cb",
		Secure:   true,
		HttpOnly: true,

		Expires: farPastExpiryTime,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) getOAuth2CookieName(state string) (string, error) {
	return "__my_state_cookie__", nil
}
