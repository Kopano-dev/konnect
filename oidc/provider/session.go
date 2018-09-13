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

package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/payload"
)

func (p *Provider) getOrCreateSession(rw http.ResponseWriter, req *http.Request, ar *payload.AuthenticationRequest, auth identity.AuthRecord) (*payload.Session, error) {
	var session *payload.Session
	serialized, err := p.getSessionCookie(req)
	if err == nil {
		// Decode.
		session, err = p.unserializeSession(serialized)
		if err != nil {
			p.logger.WithError(err).Debugln("failed to secode client session")
		}
	}
	if session != nil && session.Sub == auth.Subject() {
		// Existing session with same sub.
		return session, nil
	}

	// Create new session.
	session = &payload.Session{
		ID:  rndm.GenerateRandomString(32),
		Sub: auth.Subject(),
	}

	serialized, err = p.serializeSession(session)
	if err != nil {
		return session, err
	}
	err = p.setSessionCookie(rw, serialized)

	return session, err
}

func (p *Provider) serializeSession(session *payload.Session) (string, error) {
	var b bytes.Buffer
	enc := gob.NewEncoder(&b)
	err := enc.Encode(session)
	if err != nil {
		return "", err
	}

	ciphertext, err := p.encryptionManager.Encrypt(b.Bytes())
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (p *Provider) unserializeSession(value string) (*payload.Session, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}

	raw, err := p.encryptionManager.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	var session payload.Session

	r := bytes.NewReader(raw)
	dec := gob.NewDecoder(r)

	err = dec.Decode(&session)
	if err != nil {
		return nil, err
	}

	return &session, nil
}

func (p *Provider) getUserIDAndSessionRefFromClaims(claims *jwt.StandardClaims, identityClaims jwt.MapClaims) (string, *string) {
	if claims == nil || identityClaims == nil {
		return "", nil
	}

	var userID string
	userID, _ = identityClaims[konnect.IdentifiedUserIDClaim].(string)
	if userID == "" {
		return "", nil
	}

	return userID, identity.GetSessionRef(p.identityManager.Name(), claims.Audience, userID)
}
