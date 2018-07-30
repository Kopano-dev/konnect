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

package provider

import (
	"fmt"
	"net/http"
	"net/url"
)

func uniqueStrings(s []string) []string {
	var res []string
	m := make(map[string]bool)
	for _, s := range s {
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = true
		res = append(res, s)
	}

	return res
}

func getRequestURL(req *http.Request, isTrustedSource bool) *url.URL {
	u, _ := url.Parse(req.URL.String())

	if isTrustedSource {
		// Look at proxy injected values to rewrite URLs if trusted.
		for {
			prefix := req.Header.Get("X-Forwarded-Prefix")
			if prefix != "" {
				u.Path = fmt.Sprintf("%s%s", prefix, u.Path)
				break
			}
			replaced := req.Header.Get("X-Replaced-Path")
			if replaced != "" {
				u.Path = replaced
				break
			}

			break
		}
	}

	return u
}

func addResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "origin")
}

func makeArrayFromBoolMap(m map[string]bool) []string {
	result := []string{}
	for k, v := range m {
		if v {
			result = append(result, k)
		}
	}

	return result
}
