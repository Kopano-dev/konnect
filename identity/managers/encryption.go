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
	"fmt"

	"stash.kopano.io/kc/konnect/encryption"
)

// EncryptionManager implements string encryption functions with a key.
type EncryptionManager struct {
	key *[encryption.KeySize]byte
}

// NewEncryptionManager creates a new EncryptionManager with the provided key.
func NewEncryptionManager(key *[encryption.KeySize]byte) (*EncryptionManager, error) {
	em := &EncryptionManager{
		key: key,
	}

	return em, nil
}

// SetKey sets the provided key for the accociated manager.
func (em *EncryptionManager) SetKey(key []byte) error {
	switch len(key) {
	case encryption.KeySize:
		// all good, breaks
	case hex.EncodedLen(encryption.KeySize):
		// try to decode with hex
		dst := make([]byte, encryption.KeySize)
		if _, err := hex.Decode(dst, key); err == nil {
			key = dst
		}
	}
	if len(key) != encryption.KeySize {
		return fmt.Errorf("encryption key size error, is %d, want %d", len(key), encryption.KeySize)
	}

	em.key = new([encryption.KeySize]byte)
	copy(em.key[:], key[:encryption.KeySize])
	return nil
}

// EncryptStringToHexString encrypts a plaintext string with the accociated
// key and returns the hex encoded ciphertext as string.
func (em *EncryptionManager) EncryptStringToHexString(plaintext string) (string, error) {
	ciphertext, err := em.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(ciphertext), nil
}

// Encrypt encrypts plaintext []byte with the accociated key and returns
// ciphertext []byte.
func (em *EncryptionManager) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := encryption.Encrypt(plaintext, em.key)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptHexToString decrypts a hex encoded string with the accociated key
// and returns the plain text as string.
func (em *EncryptionManager) DecryptHexToString(ciphertextHex string) (string, error) {
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}
	plaintext, err := em.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Decrypt decrypts ciphertext []byte with the accociated key and returns
// plaintext []byte.
func (em *EncryptionManager) Decrypt(ciphertext []byte) ([]byte, error) {
	plaintext, err := encryption.Decrypt(ciphertext, em.key)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
