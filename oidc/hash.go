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
	"crypto"
	"encoding/base64"
	"fmt"
)

// LeftmostHashBytes defines []bytes with Base64URL encoder via String().
type LeftmostHashBytes []byte

// LeftmostHash hashes the provided data with the provided hash function and
// returns the left-most half the hashed bytes.
func LeftmostHash(data []byte, hash crypto.Hash) LeftmostHashBytes {
	hasher := hash.New()
	hasher.Write(data)
	result := hasher.Sum(nil)

	return LeftmostHashBytes(result[:len(result)/2])
}

// String returns the Base64URL encoded string of the accociated bytes.
func (lmhb LeftmostHashBytes) String() string {
	return base64.URLEncoding.EncodeToString(lmhb)
}

// HashFromSigningMethod returns the matching crypto.Hash for the provided
// signing alg.
func HashFromSigningMethod(alg string) (hash crypto.Hash, err error) {
	switch alg {
	case "HS256":
		fallthrough
	case "RS256":
		fallthrough
	case "PS256":
		fallthrough
	case "ES256":
		hash = crypto.SHA256

	case "HS386":
		fallthrough
	case "RS384":
		fallthrough
	case "PS384":
		fallthrough
	case "ES384":
		hash = crypto.SHA384

	case "HS512":
		fallthrough
	case "RS512":
		fallthrough
	case "PS512":
		fallthrough
	case "ES512":
		hash = crypto.SHA512

	default:
		err = fmt.Errorf("Unkown alg %s", alg)
	}

	if !hash.Available() {
		err = fmt.Errorf("Hash for %s is not available", alg)
	}

	return
}
