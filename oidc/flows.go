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

// OIDC response types and flows.
const (
	ResponseTypeCode             = "code"                // OIDC code flow
	ResponseTypeIDTokenToken     = "id_token token"      // OIDC implicit flow
	ResponseTypeIDToken          = "id_token"            // OIDC implicit flow
	ResponseTypeCodeIDToken      = "code id_token"       // OIDC hybrid flow
	ResponseTypeCodeToken        = "code token"          // OIDC hybrid flow
	ResponseTypeCodeIDTokenToken = "code id_token token" // OIDC hybrid flow
	ResponseTypeToken            = "token"               // OAuth2

	ResponseModeFragment = "fragment"
	ResponseModeQuery    = "query"

	FlowCode     = "code"
	FlowImplicit = "implicit"
	FlowHybrid   = "hybrid"
)
