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

	"github.com/google/go-querystring/query"
)

func redirect(rw http.ResponseWriter, code int, uri *url.URL, params interface{}, asFragment bool) error {
	var uriString string

	if params != nil {
		queryString, err := query.Values(params)
		if err != nil {
			return err
		}

		if asFragment {
			uriString = fmt.Sprintf("%s#%s", uri.String(), queryString.Encode())
		} else {
			uri.RawQuery = queryString.Encode()
			uriString = uri.String()
		}
	} else {
		uriString = uri.String()
	}

	rw.Header().Set("Location", uriString)
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rw.WriteHeader(code)

	return nil
}
