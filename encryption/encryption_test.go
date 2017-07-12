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
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	defaultSecretKey     [KeySize]byte
	defaultNonce         [NonceSize]byte
	defaultPlainText     []byte
	defaultEncryptedText []byte
)

func init() {
	secretKey, _ := hex.DecodeString("0f9c41164bab0d26fd4e1d50ea7323b294a5cd4c5bc79dbfd667b0d870bdd11e")
	copy(defaultSecretKey[:], secretKey[:KeySize])

	nonce, _ := hex.DecodeString("87e0e8c89c58eda1ced9aa829e1f32d8837c5f9660717a49")
	copy(defaultNonce[:], nonce[:NonceSize])

	defaultPlainText = []byte("We are Kopano, and we empower you to have choice to use multiple ways to communicate with others, be it email, video meetings or chat.")

	defaultEncryptedText, _ = hex.DecodeString("87e0e8c89c58eda1ced9aa829e1f32d8837c5f9660717a4947526753dbe3a493d2c97961591c0d05dd7525ca34165ac1aeb0950789cfd3f8a8c8e981f564494c0a8cb039bf14d844af6dfb107af432160d58e3ff544f28c00f1b27ebcc12424b19bc2325fdb31513da4b45731adc004b05b3fe821038f77097bffb4507e9d7a79b86cb1318e1bfe4ab7a84d01888daa916470238fe71d7d83c16fd6066d672cd491b29f590fcfada5a0c89386d31")
}

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}

	if len(nonce) != NonceSize {
		t.Fatalf("nonce has wrong size: got %v want %v", len(nonce), NonceSize)
	}
}

func TestGenerateKey(t *testing.T) {
	secretKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(secretKey) != KeySize {
		t.Fatalf("secret key has wrong size: got %v want %v", len(secretKey), KeySize)
	}
}

func TestEncryptWithNonce(t *testing.T) {
	msg := []byte(defaultPlainText)
	encrypted, err := encryptWithNonce(msg, &defaultNonce, &defaultSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encrypted, defaultEncryptedText) {
		t.Fatalf("encrypted text does not match expected value, %x", encrypted)
	}
}

func TestEncrypt(t *testing.T) {
	msg := []byte(defaultPlainText)
	encrypted, err := Encrypt(msg, &defaultSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(encrypted, defaultEncryptedText) {
		t.Fatal("encrypted text does not seem to have a nonce")
	}
}

func TestDecrypt(t *testing.T) {
	decrypted, err := Decrypt(defaultEncryptedText, &defaultSecretKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, defaultPlainText) {
		t.Fatalf("decrypted text does not match expected value, got %v", decrypted)
	}
}
