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

package encryption

import (
	"fmt"

	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// KeySize is the size of the keys created by GenerateKey()
	KeySize = 32
	// NonceSize is the size of the nonces created by GenerateNonce()
	NonceSize = 24
)

// Encrypt generates a random nonce and encrypts the input using nacl.secretbox
// package. We store the nonce in the first 24 bytes of the encrypted text.
func Encrypt(msg []byte, key *[KeySize]byte) ([]byte, error) {
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	return encryptWithNonce(msg, nonce, key)
}

func encryptWithNonce(msg []byte, nonce *[NonceSize]byte, key *[KeySize]byte) ([]byte, error) {
	encrypted := secretbox.Seal(nonce[:], msg, nonce, key)
	return encrypted, nil
}

// Decrypt extracts the nonce from the encrypted text, and attempts to decrypt
// with nacl.box.
func Decrypt(msg []byte, key *[KeySize]byte) ([]byte, error) {
	if len(msg) < (NonceSize + secretbox.Overhead) {
		return nil, fmt.Errorf("wrong length of ciphertext")
	}

	var nonce [NonceSize]byte
	copy(nonce[:], msg[:NonceSize])
	decrypted, ok := secretbox.Open(nil, msg[NonceSize:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decrypted, nil
}
