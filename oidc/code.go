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
	"crypto/subtle"
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
	if method == "" {
		// We default to S256CodeChallengeMethod.
		method = S256CodeChallengeMethod
	}

	computed, err := MakeCodeChallenge(method, verifier)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare([]byte(challenge), []byte(computed)) != 1 {
		return errors.New("invalid code challenge")
	}
	return nil
}

// MakeCodeChallenge creates a code challenge using the provided method and
// verifier for https://tools.ietf.org/html/rfc7636#section-4.6 verification.
func MakeCodeChallenge(method string, verifier string) (string, error) {
	if verifier == "" {
		return "", errors.New("invalid verifier")
	}

	switch method {
	case PlainCodeChallengeMethod:
		// Challenge is verifier.
		return verifier, nil
	case S256CodeChallengeMethod:
		// BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
		sum := sha256.Sum256([]byte(verifier))
		return base64.URLEncoding.EncodeToString(sum[:]), nil
	}

	return "", errors.New("transform algorithm not supported")
}
