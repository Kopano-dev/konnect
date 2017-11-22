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
	"time"
)

var (
	farPastExpiryTime                 = time.Unix(0, 0)
	farPastExpiryTimeHTTPHeaderString = farPastExpiryTime.UTC().Format(http.TimeFormat)
)

func addCommonResponseHeaders(header http.Header) {
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-XSS-Protection", "1; mode=block")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "origin")
}

func addNoCacheResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	header.Set("Pragma", "no-cache")
	header.Set("Expires", farPastExpiryTimeHTTPHeaderString)
}
