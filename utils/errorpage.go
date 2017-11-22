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
	"fmt"
	"net/http"
)

// WriteErrorPage create a formatted error page response containing the provided
// information and writes it to the provided http.ResponseWriter.
func WriteErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	if title == "" {
		title = http.StatusText(code)
	}

	text := fmt.Sprintf("%d %s", code, title)
	if message != "" {
		text = text + " - " + message
	}

	http.Error(rw, text, code)
}
