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

package identity

import (
	"net/url"
)

// IsHandledError is an error which tells that the backend has handled
// the request and all further handling should stop
type IsHandledError struct {
}

// Error implements the error interface.
func (err *IsHandledError) Error() string {
	return "is_handled"
}

// RedirectError is an error which backends can return if a
// redirection is required.
type RedirectError struct {
	id          string
	redirectURI *url.URL
}

// NewRedirectError creates a new corresponding error with the
// provided id and redirect URL.
func NewRedirectError(id string, redirectURI *url.URL) *RedirectError {
	return &RedirectError{
		id:          id,
		redirectURI: redirectURI,
	}
}

// Error implements the error interface.
func (err *RedirectError) Error() string {
	return err.id
}

// RedirectURI returns the redirection URL of the accociated error.
func (err *RedirectError) RedirectURI() *url.URL {
	return err.redirectURI
}
