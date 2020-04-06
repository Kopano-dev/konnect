/*
 * Copyright 2017-2020 Kopano and its licensors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package identifier

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/oidc-go"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect/identity/authorities"
	konnectoidc "stash.kopano.io/kc/konnect/oidc"

	"stash.kopano.io/kc/konnect/utils"
)

func (i *Identifier) writeSAML2Start(rw http.ResponseWriter, req *http.Request, authority *authorities.Details) {
	var err error

	if authority == nil {
		err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2TemporarilyUnavailable, "no authority")
	} else if !authority.IsReady() {
		err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2TemporarilyUnavailable, "authority not ready")
	}

	switch typedErr := err.(type) {
	case nil:
		// breaks
	case *konnectoidc.OAuth2Error:
		// Redirect back, with error.
		i.logger.WithFields(utils.ErrorAsFields(err)).Debugln("saml2 start error")
		// NOTE(longsleep): Pass along error ID but not the description to avoid
		// leaking potentially internal information to our RP.
		uri, _ := url.Parse(i.authorizationEndpointURI.String())
		query, _ := url.ParseQuery(req.URL.RawQuery)
		query.Del("flow")
		query.Set("error", typedErr.ErrorID)
		query.Set("error_description", "identifier failed to authenticate")
		uri.RawQuery = query.Encode()
		utils.WriteRedirect(rw, http.StatusFound, uri, nil, false)
		return
	default:
		i.logger.WithError(err).Errorln("identifier failed to process saml2 start")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "saml2 start failed")
		return
	}

	sd := &StateData{
		State:    rndm.GenerateRandomString(32),
		RawQuery: req.URL.RawQuery,

		Ref: authority.ID,
	}

	uri, extra, err := authority.MakeRedirectAuthenticationRequestURL(sd.State)
	if err != nil {
		i.logger.WithError(err).Errorln("identifier failed to create authentication request: %w", err)
		i.ErrorPage(rw, http.StatusInternalServerError, "", "saml2 start failed")
		return
	}
	sd.Extra = extra

	// Set cookie which is consumed by the callback later.
	err = i.SetStateToStateCookie(req.Context(), rw, "saml2/acs", sd)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to set saml2 state cookie")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to set cookie")
		return
	}

	utils.WriteRedirect(rw, http.StatusFound, uri, nil, false)
}

func (i *Identifier) writeSAML2AssertionConsumerService(rw http.ResponseWriter, req *http.Request) {
	var err error
	var sd *StateData
	var user *IdentifiedUser
	var authority *authorities.Details

	for {
		sd, err = i.GetStateFromStateCookie(req.Context(), rw, req, "saml2/acs", req.Form.Get("RelayState"))
		if err != nil {
			err = fmt.Errorf("failed to decode saml2 acs state: %v", err)
			break
		}
		if sd == nil {
			err = errors.New("state not found")
			break
		}

		// Load authority with client_id in state.
		authority, _ = i.authorities.Lookup(req.Context(), sd.Ref)
		if authority == nil {
			i.logger.Debugln("identifier failed to find authority in saml2 acs")
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2InvalidRequest, "unknown client_id")
			break
		}

		if authority.AuthorityType != authorities.AuthorityTypeSAML2 {
			err = errors.New("unknown authority type")
			break
		}

		// Parse incoming state response.
		var assertion *saml.Assertion
		if assertionRaw, parseErr := authority.ParseStateResponse(req, sd.State, sd.Extra); parseErr == nil {
			assertion = assertionRaw.(*saml.Assertion)
		} else {
			err = parseErr
			break
		}

		// Lookup username and user.
		un, claimsErr := authority.IdentityClaimValue(assertion)
		if claimsErr != nil {
			i.logger.WithError(claimsErr).Debugln("identifier failed to get username from saml2 acs assertion")
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2InsufficientScope, "identity claim not found")
			break
		}

		username := &un

		user, err = i.resolveUser(req.Context(), *username)
		if err != nil {
			i.logger.WithError(err).WithField("username", *username).Debugln("identifier failed to resolve saml2 acs user with backend")
			// TODO(longsleep): Break on validation error.
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2AccessDenied, "failed to resolve user")
			break
		}
		if user == nil || user.Subject() == "" {
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2AccessDenied, "no such user")
			break
		}

		// Get user meta data.
		// TODO(longsleep): This is an additional request to the backend. This
		// should be avoided. Best would be if the backend would return everything
		// in one shot (TODO in core).
		err = i.updateUser(req.Context(), user)
		if err != nil {
			i.logger.WithError(err).Debugln("identifier failed to get user data in saml2 acs request")
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2AccessDenied, "failed to get user data")
			break
		}

		// Set logon time.
		user.logonAt = time.Now()

		err = i.SetUserToLogonCookie(req.Context(), rw, user)
		if err != nil {
			i.logger.WithError(err).Errorln("identifier failed to serialize logon ticket in saml2 acs")
			i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to serialize logon ticket")
			return
		}

		break
	}

	if sd == nil {
		i.logger.WithError(err).Debugln("identifier saml2 acs without state")
		i.ErrorPage(rw, http.StatusBadRequest, "", "state not found")
		return
	}

	uri, _ := url.Parse(i.authorizationEndpointURI.String())
	query, _ := url.ParseQuery(sd.RawQuery)
	query.Del("flow")
	query.Set("identifier", MustBeSignedIn)

	switch typedErr := err.(type) {
	case nil:
		// breaks
	case *saml.InvalidResponseError:
		i.logger.WithError(err).WithFields(logrus.Fields{
			"reason": typedErr.PrivateErr,
		}).Debugf("saml2 acs invalid response")
		query.Set("error", oidc.ErrorCodeOAuth2AccessDenied)
		query.Set("error_description", "identifier received invalid response")
		// breaks
	case *konnectoidc.OAuth2Error:
		// Pass along OAuth2 error.
		i.logger.WithFields(utils.ErrorAsFields(err)).Debugln("saml2 acs error")
		// NOTE(longsleep): Pass along error ID but not the description to avoid
		// leaking potetially internal information to our RP.
		query.Set("error", typedErr.ErrorID)
		query.Set("error_description", "identifier failed to authenticate")
		//breaks
	default:
		i.logger.WithError(err).Errorln("identifier failed to process saml2 acs")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "saml2 acs failed")
		return
	}

	uri.RawQuery = query.Encode()
	utils.WriteRedirect(rw, http.StatusFound, uri, nil, false)
}
