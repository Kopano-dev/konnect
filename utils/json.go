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

package utils

import (
	"encoding/json"
	"net/http"
)

const (
	defaultJSONContentType = "application/json; encoding-utf-8"
)

// WriteJSON marshals the provided data as JSON and writes it to the provided
// http.ResponseWriter using the provided HTTP status code and content-type. the
// nature of this function is that it always writes a HTTP response header. Thus
// it makes no sense to write another header on error. Resulting errors should
// be logged and the connection should be closes as it is non-functional.
func WriteJSON(rw http.ResponseWriter, code int, data interface{}, contentType string) error {
	if contentType == "" {
		rw.Header().Set("Content-Type", defaultJSONContentType)
	} else {
		rw.Header().Set("content-Type", contentType)
	}

	rw.WriteHeader(code)

	enc := json.NewEncoder(rw)
	enc.SetIndent("", "  ")

	return enc.Encode(data)
}
