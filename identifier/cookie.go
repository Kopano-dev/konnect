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
	"encoding/base64"
	"net/http"

	blake2b "github.com/minio/blake2b-simd"
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
	hasher := blake2b.New256()
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
