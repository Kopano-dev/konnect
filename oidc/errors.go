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

package oidc

import (
	"fmt"
	"net/http"

	"stash.kopano.io/kc/konnect/utils"
)

// OIDC and OAuth2 error codes.
const (
	ErrorOAuth2UnsupportedResponseType = "unsupported_response_type"
	ErrorOAuth2InvalidRequest          = "invalid_request"
	ErrorOAuth2InvalidToken            = "invalid_token"
	ErrorOAuth2InsufficientScope       = "insufficient_scope"
	ErrorOAuth2InvalidGrant            = "invalid_grant"
	ErrorOAuth2UnsupportedGrantType    = "unsupported_grant_type"
	ErrorOAuth2AccessDenied            = "access_denied"
	ErrorOAuth2ServerError             = "server_error"
	ErrorOAuth2TemporarilyUnavailable  = "temporarily_unavailable"

	ErrorOIDCInteractionRequired = "interaction_required"
	ErrorOIDCLoginRequired       = "login_required"
	ErrorOIDCConsentRequired     = "consent_required"

	ErrorOIDCRequestNotSupported      = "request_not_supported"
	ErrorOIDCInvalidRequestObject     = "invalid_request_object"
	ErrorOIDCRequestURINotSupported   = "request_uri_not_supported"
	ErrorOIDCRegistrationNotSupported = "registration_not_supported"
)

// OAuth2Error defines a general OAuth2 error with id and decription.
type OAuth2Error struct {
	ErrorID          string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Error implements the error interface.
func (err *OAuth2Error) Error() string {
	return err.ErrorID
}

// Description implements the ErrorWithDescription interface.
func (err *OAuth2Error) Description() string {
	return err.ErrorDescription
}

// NewOAuth2Error creates a new error with id and description.
func NewOAuth2Error(id string, description string) utils.ErrorWithDescription {
	return &OAuth2Error{id, description}
}

// WriteWWWAuthenticateError writes the provided error with the provided
// http status code to the provided http response writer as a
// WWW-Authenticate header with comma seperated fields for id and
// description.
func WriteWWWAuthenticateError(rw http.ResponseWriter, code int, err error) {
	if code == 0 {
		code = http.StatusUnauthorized
	}

	var description string
	switch err.(type) {
	case utils.ErrorWithDescription:
		description = err.(utils.ErrorWithDescription).Description()
	default:
	}

	rw.Header().Set("WWW-Authenticate", fmt.Sprintf("error=\"%s\", error_description=\"%s\"", err.Error(), description))
	rw.WriteHeader(code)
}
