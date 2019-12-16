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

package utils

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-querystring/query"
)

// WriteRedirect crates a URL out of the provided uri and params and writes a
// a HTTP response with the provided HTTP status code to the provided
// http.ResponseWriter incliding HTTP caching headers to prevent caching. If
// asFragment is true, the provided params are added as URL fragment, otherwise
// they replace the query. If params is nil, the provided uri is taken as is.
func WriteRedirect(rw http.ResponseWriter, code int, uri *url.URL, params interface{}, asFragment bool) error {
	uriString := uri.String()

	if params != nil {
		queryString, err := query.Values(params)
		if err != nil {
			return err
		}

		separator := "#"
		if !asFragment {
			separator = "?"
		}

		if strings.Contains(uriString, separator) {
			// Avoid generating invalid URLs if the separator is already part
			// of the target URL - instead append it in the most likely way.
			separator = "&"
		}
		queryStringEncoded := strings.Replace(queryString.Encode(), "+", "%20", -1) // NOTE(longsleep): Ensure we use %20 instead of +.
		uriString = fmt.Sprintf("%s%s%s", uriString, separator, queryStringEncoded)
	}

	rw.Header().Set("Location", uriString)
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rw.WriteHeader(code)

	return nil
}
