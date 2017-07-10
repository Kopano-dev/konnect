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
	"encoding/hex"

	"stash.kopano.io/kc/konnect/encryption"
)

// TODO(longsleep): create random key, encrypt with public key and add to payload.
var defaultEncryptionKey [encryption.KeySize]byte

func init() {
	encryptionKey := []byte("AES256Key-32Characters1234567890")
	copy(defaultEncryptionKey[:], encryptionKey[:encryption.KeySize])
}

func encryptStringToHexString(plaintext string) (string, error) {
	ciphertext, err := encryption.Encrypt([]byte(plaintext), &defaultEncryptionKey)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

func decryptHexToString(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	plaintext, err := encryption.Decrypt(ciphertext, &defaultEncryptionKey)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
