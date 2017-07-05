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

const (
	// GrantTypeAuthorizationCode is the string value for the
	// OAuth2 authroization code token request grant type.
	GrantTypeAuthorizationCode = "authorization_code"

	// GrantTypeImplicit is the string value for the OAuth2 id_token, token
	// id_token token request grant type.
	GrantTypeImplicit = "implicit"

	// GrantTypeRefreshToken is the string value for the OAuth2 refresh_token
	// token request grant_type.
	GrantTypeRefreshToken = "refresh_token"
)
