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

package utils

import (
	"net/http"
	"net/url"
)

// OriginFromRequestHeaders tries to find information about the origin from the
// provided http.Header. It first looks into the Origin header field and if that
// is not found it looks into the Referer header field. If both are not found
// an empty string is returned.
func OriginFromRequestHeaders(header http.Header) string {
	origin := header.Get("Origin")
	if origin == "" {
		referer := header.Get("Referer")
		if referer != "" {
			refererURI, _ := url.Parse(referer)
			origin = refererURI.Scheme + "://" + refererURI.Host
		}
	}

	return origin
}
