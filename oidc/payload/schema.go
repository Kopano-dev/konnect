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

package payload

import (
	"encoding/json"
	"reflect"

	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()
var encoder = schema.NewEncoder()

// DecodeSchema decodes request form data into the provided dst schema struct.
func DecodeSchema(dst interface{}, src map[string][]string) error {
	return decoder.Decode(dst, src)
}

// EncodeSchema encodes the provided src schema to the provided map.
func EncodeSchema(src interface{}, dst map[string][]string) error {
	return encoder.Encode(src, dst)
}

// ConvertOIDCClaimsRequest is a converter function for oidc.ClaimsRequest data
// provided in URL schema.
func ConvertOIDCClaimsRequest(value string) reflect.Value {
	v := ClaimsRequest{}

	if err := json.Unmarshal([]byte(value), &v); err != nil {
		return reflect.Value{}
	}

	return reflect.ValueOf(v)
}

func init() {
	decoder.IgnoreUnknownKeys(true)
	decoder.RegisterConverter(ClaimsRequest{}, ConvertOIDCClaimsRequest)
}
