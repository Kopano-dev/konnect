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
	"net/http"
)

func (p *Provider) setBrowserStateCookie(rw http.ResponseWriter, value string) error {
	cookie := http.Cookie{
		Name:  p.browserStateCookieName,
		Value: value,

		Path:     p.browserStateCookiePath,
		Secure:   true,
		HttpOnly: false, // This Cookie is intended to be read by Javascript.
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (p *Provider) removeBrowserStateCookie(rw http.ResponseWriter) error {
	cookie := http.Cookie{
		Name: p.browserStateCookieName,

		Path:     p.browserStateCookiePath,
		Secure:   true,
		HttpOnly: false, // This Cookie is intended to be read by Javascript.

		Expires: farPastExpiryTime,
	}
	http.SetCookie(rw, &cookie)

	return nil
}
