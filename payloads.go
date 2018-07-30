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

package konnect

import (
	"encoding/json"

	"stash.kopano.io/kc/konnect/oidc/payload"
)

// UserInfoResponse defines the data returned from the Konnect UserInfo
// endpoint. It is the standard ODIC response, extended with additional claims.
type UserInfoResponse struct {
	*payload.UserInfoResponse

	*IDClaims
	*UniqueUserIDClaims
}

// Map converts the accociated UserInfoResponse to a map which can be
// extended to attach additional claims.
func (uir *UserInfoResponse) Map() (map[string]interface{}, error) {
	// NOTE(longsleep): This implementation sucks, marshal to JSON and unmarshal
	// again - rly?
	intermediate, err := json.Marshal(uir)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]interface{})
	err = json.Unmarshal(intermediate, &claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}
