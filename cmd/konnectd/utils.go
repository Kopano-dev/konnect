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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/dgrijalva/jwt-go"
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

		ecKey, errParse3 := x509.ParseECPrivateKey(block.Bytes)
		if errParse3 == nil {
			signer = ecKey
			break
		}

		return nil, fmt.Errorf("failed to parse signer key - valid PKCS#1, PKCS#8 ...? %v, %v, %v", errParse1, errParse2, errParse3)
	}

	return signer, nil
}

func loadValidatorFromFile(fn string) (crypto.PublicKey, error) {
	pemBytes, errRead := ioutil.ReadFile(fn)
	if errRead != nil {
		return nil, fmt.Errorf("failed to parse key file: %v", errRead)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var validator crypto.PublicKey
	for {
		pkcs1PubKey, errParse1 := x509.ParsePKCS1PublicKey(block.Bytes)
		if errParse1 == nil {
			validator = pkcs1PubKey
			break
		}

		pkcs1PrivKey, errParse2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if errParse2 == nil {
			validator = pkcs1PrivKey.Public()
			break
		}

		pkcs8Key, errParse3 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errParse3 == nil {
			signerSigner, ok := pkcs8Key.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("failed to use key as crypto signer")
			}
			validator = signerSigner.Public()
			break
		}

		ecKey, errParse4 := x509.ParseECPrivateKey(block.Bytes)
		if errParse4 == nil {
			validator = ecKey.Public()
			break
		}

		return nil, fmt.Errorf("failed to parse validator key - valid PKCS#1, PKCS#8 ...? %v, %v, %v, %v", errParse1, errParse2, errParse3, errParse4)
	}

	return validator, nil
}

func addSignerWithIDFromFile(fn string, id string, bs *bootstrap) error {
	fi, err := os.Lstat(fn)
	if err != nil {
		return fmt.Errorf("failed load load signer key: %v", err)
	}

	mode := fi.Mode()
	switch {
	case mode.IsDir():
		return fmt.Errorf("signer key must be a file")
	}

	// Load file.
	signer, err := loadSignerFromFile(fn)
	if err != nil {
		return err
	}

	// Validate signing method
	switch bs.signingMethod.(type) {
	case *jwt.SigningMethodRSA:
		rsaPrivateKey, ok := signer.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("wrong signing method for signing key (signing method is %s)", bs.signingMethod.Alg())
		}
		// Ensure the private key is not vulnerable with PKCS-1.5 signatures. See
		// https://paragonie.com/blog/2018/04/protecting-rsa-based-protocols-against-adaptive-chosen-ciphertext-attacks#rsa-anti-bb98
		// for details.
		if rsaPrivateKey.PublicKey.E < 65537 {
			return fmt.Errorf("RSA signing key with public exponent < 65537")
		}
	case *jwt.SigningMethodRSAPSS:
		if _, ok := signer.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("wrong signing method for signing key (signing method is %s)", bs.signingMethod.Alg())
		}
	case *jwt.SigningMethodECDSA:
		if _, ok := signer.(*ecdsa.PrivateKey); !ok {
			return fmt.Errorf("wrong signing method for signing key (signing method is %s)", bs.signingMethod.Alg())
		}
	default:
		return fmt.Errorf("unsupported signing method: %s", bs.signingMethod.Alg())
	}

	if id == "" {
		// Get ID from file, following symbolic link.
		var real string
		if mode&os.ModeSymlink != 0 {
			real, err = os.Readlink(fn)
			if err != nil {
				return err
			}
			_, real = filepath.Split(real)
		} else {
			real = fi.Name()
		}

		id = getKeyIDFromFilename(real)
	}

	bs.signers[id] = signer
	if bs.signingKeyID == "" {
		// Set as default if none is set.
		bs.signingKeyID = id
	}

	return nil
}

func addValidatorsFromPath(pn string, bs *bootstrap) error {
	fi, err := os.Lstat(pn)
	if err != nil {
		return fmt.Errorf("failed load load validator keys: %v", err)
	}

	switch mode := fi.Mode(); {
	case mode.IsDir():
		// OK.
	default:
		return fmt.Errorf("validator path must be a directory")
	}

	// Load all files.
	files, err := filepath.Glob(filepath.Join(pn, "*.pem"))
	if err != nil {
		return fmt.Errorf("validator path err: %v", err)
	}

	for _, file := range files {
		validator, err := loadValidatorFromFile(file)
		if err != nil {
			bs.cfg.Logger.WithError(err).WithField("path", file).Warnln("failed to load validator key")
			continue
		}

		// Get ID from file, without following symbolic links.
		_, fn := filepath.Split(file)
		bs.validators[getKeyIDFromFilename(fn)] = validator
	}

	return nil
}

func withSchemeAndHost(u, base *url.URL) *url.URL {
	if u.Host != "" && u.Scheme != "" {
		return u
	}

	r, _ := url.Parse(u.String())
	r.Scheme = base.Scheme
	r.Host = base.Host

	return r
}

func getKeyIDFromFilename(fn string) string {
	ext := filepath.Ext(fn)
	return strings.TrimSuffix(fn, ext)
}
