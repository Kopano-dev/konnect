/*
 * Copyright 2019 Kopano and its licensors
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

package identifier

import (
	"github.com/gorilla/schema"
)

// Create a Decoder instance as a package global, because it caches
// meta-data about structs, and an instance can be shared safely.
var urlSchemaDecoder = schema.NewDecoder()

// DecodeURLSchema decodes request for mdata in to the provided dst url struct.
func DecodeURLSchema(dst interface{}, src map[string][]string) error {
	return urlSchemaDecoder.Decode(dst, src)
}

func init() {
	urlSchemaDecoder.SetAliasTag("url")
	urlSchemaDecoder.IgnoreUnknownKeys(true)
}
