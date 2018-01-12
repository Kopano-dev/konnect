/*
 * Copyright 2018 Kopano and its licensors
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

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

func loadSignerFromFile(fn string) (crypto.Signer, error) {
	pemBytes, errRead := ioutil.ReadFile(fn)
	if errRead != nil {
		return nil, fmt.Errorf("failed to parse key file: %v", errRead)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var signer crypto.Signer
	for {
		pkcs1Key, errParse1 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if errParse1 == nil {
			signer = pkcs1Key
			break
		}

		pkcs8Key, errParse2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse2 == nil {
			signerSigner, ok := pkcs8Key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("failed to use key as crypto signer")
			}
			signer = signerSigner
			break
		}

		return nil, fmt.Errorf("failed to parse key - valid PKCS#1 or PKCS#8? %v, %v", errParse1, errParse2)
	}

	return signer, nil
}

func loadKeys(fn string, defaultLabel string) (map[string]crypto.Signer, map[string]crypto.PublicKey, error) {
	fi, err := os.Stat(fn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed load load keys: %v", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		// load all from directory.
		return nil, nil, fmt.Errorf("key directory not implemented")
	default:
		// file
		signer, err := loadSignerFromFile(fn)
		if err != nil {
			return nil, nil, err
		}

		signers := make(map[string]crypto.Signer)
		signers[defaultLabel] = signer

		return signers, nil, nil
	}
}
