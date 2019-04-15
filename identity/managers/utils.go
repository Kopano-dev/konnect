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

package managers

import (
	"encoding/base64"

	"golang.org/x/crypto/blake2b"

	konnectoidc "stash.kopano.io/kc/konnect/oidc"
)

func setupSupportedScopes(scopes []string, extra []string, override []string) []string {
	if len(override) > 0 {
		return override
	}

	return append(scopes, extra...)
}

func getPublicSubject(sub []byte, extra []byte) (string, error) {
	// Hash the raw subject with a konnect specific salt.
	hasher, err := blake2b.New512([]byte(konnectoidc.KonnectIDTokenSubjectSaltV1))
	if err != nil {
		return "", err
	}

	hasher.Write(sub)
	hasher.Write([]byte(" "))
	hasher.Write(extra)

	// NOTE(longsleep): URL safe encoding for subject is important since many
	// third party applications validate this with rather strict patterns.
	s := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
	return s + "@konnect", nil
}
