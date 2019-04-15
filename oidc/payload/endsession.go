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

package payload

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dgrijalva/jwt-go"
	"stash.kopano.io/kgol/oidc-go"

	konnectoidc "stash.kopano.io/kc/konnect/oidc"
)

// EndSessionRequest holds the incoming parameters and request data for OpenID
// Connect Session Management 1.0 RP initiaed logout requests as specified at
// https://openid.net/specs/openid-connect-session-1_0.html#RPLogout
type EndSessionRequest struct {
	providerMetadata *oidc.WellKnown

	RawIDTokenHint           string `schema:"id_token_hint"`
	RawPostLogoutRedirectURI string `schema:"post_logout_redirect_uri"`
	State                    string `schema:"state"`

	IDTokenHint           *jwt.Token `schema:"-"`
	PostLogoutRedirectURI *url.URL   `schema:"-"`
}

// DecodeEndSessionRequest returns a EndSessionRequest holding the
// provided requests form data.
func DecodeEndSessionRequest(req *http.Request, providerMetadata *oidc.WellKnown) (*EndSessionRequest, error) {
	return NewEndSessionRequest(req.Form, providerMetadata)
}

// NewEndSessionRequest returns a EndSessionRequest holding the
// provided url values.
func NewEndSessionRequest(values url.Values, providerMetadata *oidc.WellKnown) (*EndSessionRequest, error) {
	esr := &EndSessionRequest{
		providerMetadata: providerMetadata,
	}
	err := DecodeSchema(esr, values)
	if err != nil {
		return nil, err
	}

	esr.PostLogoutRedirectURI, _ = url.Parse(esr.RawPostLogoutRedirectURI)

	return esr, nil
}

// Validate validates the request data of the accociated endSession request.
func (esr *EndSessionRequest) Validate(keyFunc jwt.Keyfunc) error {
	if esr.RawIDTokenHint != "" {
		parser := &jwt.Parser{
			SkipClaimsValidation: true,
		}
		idTokenHint, err := parser.ParseWithClaims(esr.RawIDTokenHint, &konnectoidc.IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			if keyFunc != nil {
				return keyFunc(token)
			}

			return nil, fmt.Errorf("Not validated")
		})
		if err != nil {
			return esr.NewBadRequest(oidc.ErrorCodeOAuth2InvalidRequest, err.Error())
		}
		esr.IDTokenHint = idTokenHint
	}

	return nil
}

// Verify checks that the passed parameters match the accociated requirements.
func (esr *EndSessionRequest) Verify(userID string) error {
	if esr.IDTokenHint != nil {
		// Compare userID with IDTokenHint.
		if userID != esr.IDTokenHint.Claims.(*konnectoidc.IDTokenClaims).Subject {
			return esr.NewBadRequest(oidc.ErrorCodeOAuth2InvalidRequest, "userid mismatch")
		}
	}

	return nil
}

// NewError creates a new error with id and string and the associated request's
// state.
func (esr *EndSessionRequest) NewError(id string, description string) *AuthenticationError {
	return &AuthenticationError{
		ErrorID:          id,
		ErrorDescription: description,
		State:            esr.State,
	}
}

// NewBadRequest creates a new error with id and string and the associated
// request's state.
func (esr *EndSessionRequest) NewBadRequest(id string, description string) *AuthenticationBadRequest {
	return &AuthenticationBadRequest{
		ErrorID:          id,
		ErrorDescription: description,
		State:            esr.State,
	}
}
