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
	"net/http"

	jwt "gopkg.in/square/go-jose.v2/jwt"
)

func (i *Identifier) setLogonCookie(rw http.ResponseWriter, user *IdentifiedUser) error {
	// Encrypt cookie value.
	claims := jwt.Claims{
		Subject: user.Subject(),
	}
	serialized, err := jwt.Encrypted(i.encrypter).Claims(claims).Claims(user.Claims()).CompactSerialize()
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:  i.logonCookieName,
		Value: serialized,

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
