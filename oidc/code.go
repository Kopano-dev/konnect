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

package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Code challenge methods implemented by Konnect. See https://tools.ietf.org/html/rfc7636.
const (
	PlainCodeChallengeMethod = "plain"
	S256CodeChallengeMethod  = "S256"
)

// ValidateCodeChallenge implements https://tools.ietf.org/html/rfc7636#section-4.6
// code challenge verification.
func ValidateCodeChallenge(challenge string, method string, verifier string) error {
	var err error

	switch method {
	case PlainCodeChallengeMethod:
		if challenge != verifier {
			err = errors.New("invalid code challenge")
		}
	case "":
		// We default to S256CodeChallengeMethod.
		fallthrough
	case S256CodeChallengeMethod:
		// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
		sum := sha256.Sum256([]byte(verifier))
		if challenge != base64.URLEncoding.EncodeToString(sum[:]) {
			err = errors.New("invalid code challenge")
		}

	default:
		err = errors.New("transform algorithm not supported")
	}

	return err
}
