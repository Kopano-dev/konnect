/*
 * Copyright 2017-2019 Kopano and its licensors
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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"stash.kopano.io/kgol/rndm"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"stash.kopano.io/kgol/oidc-go"

	"stash.kopano.io/kc/konnect/identifier/meta"
	"stash.kopano.io/kc/konnect/identifier/meta/scopes"
	"stash.kopano.io/kc/konnect/identity/authorities"

	konnectoidc "stash.kopano.io/kc/konnect/oidc"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/utils"
)

func (i *Identifier) staticHandler(handler http.Handler, cache bool) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		addCommonResponseHeaders(rw.Header())
		if cache {
			rw.Header().Set("Cache-Control", "max-age=3153600, public")
		} else {
			rw.Header().Set("Cache-Control", "no-cache, max-age=0, public")
		}
		if strings.HasSuffix(req.URL.Path, "/") {
			// Do not serve folder-ish resources.
			i.ErrorPage(rw, http.StatusNotFound, "", "")
			return
		}
		handler.ServeHTTP(rw, req)
	})
}

func (i *Identifier) secureHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		var err error

		// TODO(longsleep): Add support for X-Forwareded-Host with trusted proxy.
		// NOTE: this does not protect from DNS rebinding. Protection for that
		// should be added at the frontend proxy.
		requiredHost := req.Host

		// This follows https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
		for {
			if req.Header.Get("Kopano-Konnect-XSRF") != "1" {
				err = fmt.Errorf("missing xsrf header")
				break
			}

			origin := req.Header.Get("Origin")
			referer := req.Header.Get("Referer")

			// Require either Origin and Referer header.
			// NOTE(longsleep): Firefox does not send Origin header for POST
			// requests when on the same domain - this is fuck (tm). See
			// https://bugzilla.mozilla.org/show_bug.cgi?id=446344 for reference.
			if origin == "" && referer == "" {
				err = fmt.Errorf("missing origin or referer header")
				break
			}

			if origin != "" {
				originURL, urlParseErr := url.Parse(origin)
				if urlParseErr != nil {
					err = fmt.Errorf("invalid origin value: %v", urlParseErr)
					break
				}
				if originURL.Host != requiredHost {
					err = fmt.Errorf("origin does not match request URL")
					break
				}
			} else if referer != "" {
				refererURL, urlParseErr := url.Parse(referer)
				if urlParseErr != nil {
					err = fmt.Errorf("invalid referer value: %v", urlParseErr)
					break
				}
				if refererURL.Host != requiredHost {
					err = fmt.Errorf("referer does not match request URL")
					break
				}
			} else {
				i.logger.WithFields(logrus.Fields{
					"host":       requiredHost,
					"user-agent": req.UserAgent(),
				}).Warn("identifier HTTP request is insecure with no Origin and Referer")
			}

			handler.ServeHTTP(rw, req)
			return
		}

		if err != nil {
			i.logger.WithError(err).WithFields(logrus.Fields{
				"host":       requiredHost,
				"referer":    req.Referer(),
				"user-agent": req.UserAgent(),
				"origin":     req.Header.Get("Origin"),
			}).Warn("rejecting identifier HTTP request")
		}

		i.ErrorPage(rw, http.StatusBadRequest, "", "")
	})
}

func (i *Identifier) handleIdentifier(rw http.ResponseWriter, req *http.Request) {
	addCommonResponseHeaders(rw.Header())
	addNoCacheResponseHeaders(rw.Header())

	err := req.ParseForm()
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request")
		return
	}

	switch req.Form.Get("flow") {
	case FlowOIDC:
		fallthrough
	case FlowOAuth:
		fallthrough
	case "":
		//  Check if there is a default authority, if so use that.
		authority := i.authorities.Default(req.Context())
		if authority != nil {
			i.newOAuth2Start(rw, req, authority)
			return
		}
	}

	// Show default.
	i.newIdentifierDefault(rw, req)
}

func (i *Identifier) newIdentifierDefault(rw http.ResponseWriter, req *http.Request) {
	nonce := rndm.GenerateRandomString(32)

	// FIXME(longsleep): Set a secure CSP. Right now we need `data:` for images
	// since it is used. Since `data:` URLs possibly could allow xss, a better
	// way should be found for our early loading inline SVG stuff.
	rw.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'nonce-%s'; base-uri 'none'; frame-ancestors 'none';", nonce))

	// Write index with random nonce to response.
	index := bytes.Replace(i.webappIndexHTML, []byte("__CSP_NONCE__"), []byte(nonce), 1)
	rw.Write(index)
}

func (i *Identifier) handleLogon(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var r LogonRequest
	err := decoder.Decode(&r)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode logon request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request JSON")
		return
	}

	var user *IdentifiedUser
	response := &LogonResponse{
		State: r.State,
	}

	addNoCacheResponseHeaders(rw.Header())

	if r.Hello != nil {
		err = r.Hello.parse()
		if err != nil {
			i.logger.WithError(err).Debugln("identifier failed to parse logon request hello")
			i.ErrorPage(rw, http.StatusBadRequest, "", "failed to parse request values")
			return
		}
	}

	// Params is an array like this [$username, $password, $mode], defining a
	// extensible way to extend login modes over time. The minimal length of
	// the params array is 1 with only [$username]. Second field is the password
	// but its interpretation depends on the third field ($mode). The rest of the
	// fields are mode specific.
	params := r.Params
	for {
		paramSize := len(params)
		if paramSize == 0 {
			i.ErrorPage(rw, http.StatusBadRequest, "", "params required")
			break
		}

		if paramSize >= 3 && params[1] == "" && params[2] == ModeLogonUsernameEmptyPasswordCookie {
			// Special mode to allow when same user is logged in via cookie. This
			// is used in the select account page logon flow with empty password.
			identifiedUser, cookieErr := i.GetUserFromLogonCookie(req.Context(), req, 0, true)
			if cookieErr != nil {
				i.logger.WithError(cookieErr).Debugln("identifier failed to decode logon cookie in logon request")
			}
			if identifiedUser != nil {
				if identifiedUser.Username() == params[0] {
					user = identifiedUser
					break
				}
			}
		}

		promptLogin := false
		audience := ""
		if r.Hello != nil {
			promptLogin, _ = r.Hello.Prompts[oidc.PromptLogin]
			audience = r.Hello.ClientID
		}

		if !promptLogin {
			// SSO support - check if request passed through a trusted proxy.
			trusted, _ := utils.IsRequestFromTrustedSource(req, i.Config.Config.TrustedProxyIPs, i.Config.Config.TrustedProxyNets)
			if trusted {
				// Check frontend proxy injected auth (Eg. Kerberos/NTLM).
				forwardedUser := req.Header.Get("X-Forwarded-User")
				if forwardedUser != "" {
					if forwardedUser == params[0] {
						resolvedUser, resolveErr := i.resolveUser(req.Context(), params[0])
						if resolveErr != nil {
							i.logger.WithError(resolveErr).Errorln("identifier failed to resolve user with backend")
							i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to resolve user")
							return
						}

						// Success, use resolved user.
						user = resolvedUser
					}
					break
				}
			}
		}

		if paramSize < 3 {
			// Unsupported logon mode.
			break
		}
		if params[1] == "" {
			// Empty password, stop here - never allowed in any mode.
			break
		}

		switch params[2] {
		case ModeLogonUsernamePassword:
			// Username and password validation mode.
			logonedUser, logonErr := i.logonUser(req.Context(), audience, params[0], params[1])
			if logonErr != nil {
				i.logger.WithError(logonErr).Errorln("identifier failed to logon with backend")
				i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to logon")
				return
			}
			user = logonedUser

		default:
			i.logger.Debugln("identifier unknown logon mode: %v", params[2])
		}

		break
	}

	if user == nil || user.Subject() == "" {
		rw.Header().Set("Kopano-Konnect-State", response.State)
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	// Get user meta data.
	// TODO(longsleep): This is an additional request to the backend. This
	// should be avoided. Best would be if the backend would return everything
	// in one shot (TODO in core).
	err = i.updateUser(req.Context(), user)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to update user data in logon request")
	}

	// Set logon time.
	user.logonAt = time.Now()

	if r.Hello != nil {
		hello, errHello := i.newHelloResponse(rw, req, r.Hello, user)
		if errHello != nil {
			i.logger.WithError(errHello).Debugln("rejecting identifier logon request")
			i.ErrorPage(rw, http.StatusBadRequest, "", errHello.Error())
			return
		}
		if !hello.Success {
			rw.Header().Set("Kopano-Konnect-State", response.State)
			rw.WriteHeader(http.StatusNoContent)
			return
		}

		response.Hello = hello
	}

	err = i.SetUserToLogonCookie(req.Context(), rw, user)
	if err != nil {
		i.logger.WithError(err).Errorln("failed to serialize logon ticket")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to serialize logon ticket")
		return
	}

	response.Success = true

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		i.logger.WithError(err).Errorln("logon request failed writing response")
	}
}

func (i *Identifier) handleLogoff(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var r StateRequest
	err := decoder.Decode(&r)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode logoff request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request JSON")
		return
	}

	addNoCacheResponseHeaders(rw.Header())

	ctx := req.Context()
	u, err := i.GetUserFromLogonCookie(ctx, req, 0, false)
	if err != nil {
		i.logger.WithError(err).Warnln("identifier logoff failed to get logon from ticket")
	}
	err = i.UnsetLogonCookie(ctx, u, rw)
	if err != nil {
		i.logger.WithError(err).Errorln("identifier failed to set logoff ticket")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to set logoff ticket")
		return
	}

	response := &StateResponse{
		State:   r.State,
		Success: true,
	}

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		i.logger.WithError(err).Errorln("logoff request failed writing response")
	}
}

func (i *Identifier) handleConsent(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var r ConsentRequest
	err := decoder.Decode(&r)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode consent request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request JSON")
		return
	}

	addNoCacheResponseHeaders(rw.Header())

	consent := &Consent{
		Allow: r.Allow,
	}
	if r.Allow {
		consent.RawScope = r.RawScope
	}

	err = i.SetConsentToConsentCookie(req.Context(), rw, &r, consent)
	if err != nil {
		i.logger.WithError(err).Errorln("failed to serialize consent ticket")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to serialize consent ticket")
		return
	}

	if !r.Allow {
		rw.Header().Set("Kopano-Konnect-State", r.State)
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	response := &StateResponse{
		State:   r.State,
		Success: true,
	}

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		i.logger.WithError(err).Errorln("logoff request failed writing response")
	}
}

func (i *Identifier) handleHello(rw http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	var r HelloRequest
	err := decoder.Decode(&r)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode hello request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request JSON")
		return
	}
	err = r.parse()
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to parse hello request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to parse request values")
		return
	}

	addNoCacheResponseHeaders(rw.Header())

	response, err := i.newHelloResponse(rw, req, &r, nil)
	if err != nil {
		i.logger.WithError(err).Debugln("rejecting identifier hello request")
		i.ErrorPage(rw, http.StatusBadRequest, "", err.Error())
		return
	}
	if !response.Success {
		rw.Header().Set("Kopano-Konnect-State", response.State)
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		i.logger.WithError(err).Errorln("hello request failed writing response")
	}
}

func (i Identifier) newHelloResponse(rw http.ResponseWriter, req *http.Request, r *HelloRequest, identifiedUser *IdentifiedUser) (*HelloResponse, error) {
	var err error
	response := &HelloResponse{
		State: r.State,
	}

handleHelloLoop:
	for {
		// Check prompt value.
		switch {
		case r.Prompts[oidc.PromptNone] == true:
			// Never show sign-in, directly return error.
			return nil, fmt.Errorf("prompt none requested")
		case r.Prompts[oidc.PromptLogin] == true:
			// Ignore all potential sources, when prompt login was requested.
			if identifiedUser != nil {
				response.Username = identifiedUser.Username()
				response.DisplayName = identifiedUser.Name()
				if response.Username != "" {
					response.Success = true
				}
			}
			break handleHelloLoop
		default:
			// Let all other prompt values pass.
		}

		if identifiedUser == nil {
			// Check if logged in via cookie.
			identifiedUser, err = i.GetUserFromLogonCookie(req.Context(), req, r.MaxAge, true)
			if err != nil {
				i.logger.WithError(err).Debugln("identifier failed to decode logon cookie in hello")
			}
		}

		if identifiedUser != nil {
			response.Username = identifiedUser.Username()
			response.DisplayName = identifiedUser.Name()
			if response.Username != "" {
				response.Success = true
				break
			}
		}

		// Check frontend proxy injected auth (Eg. Kerberos/NTLM).
		// TODO(longsleep): Add request validation before accepting incoming header.
		forwardedUser := req.Header.Get("X-Forwarded-User")
		if forwardedUser != "" {
			response.Username = forwardedUser
			response.Success = true
			break
		}

		break
	}

	if !response.Success {
		return response, nil
	}

	switch r.Flow {
	case FlowOAuth:
		fallthrough
	case FlowConsent:
		fallthrough
	case FlowOIDC:
		// TODO(longsleep): Add something to validate the parameters.
		clientDetails, err := i.clients.Lookup(req.Context(), r.ClientID, "", r.RedirectURI, "", true)
		if err != nil {
			return nil, err
		}

		promptConsent := false

		// Check prompt value.
		switch {
		case r.Prompts[oidc.PromptConsent] == true:
			promptConsent = true
		default:
			// Let all other prompt values pass.
		}

		// If not trusted, always force consent.
		if !clientDetails.Trusted {
			promptConsent = true
		}

		if promptConsent {
			// TODO(longsleep): Filter scopes to scopes we know about and all.
			response.Next = FlowConsent
			response.Scopes = r.Scopes
			response.ClientDetails = clientDetails
			response.Meta = &meta.Meta{
				Scopes: scopes.NewScopesFromIDs(r.Scopes, i.meta.Scopes),
			}
		}

		// Add authorize endpoint URI as continue URI.
		response.ContinueURI = i.authorizationEndpointURI.String()
		response.Flow = r.Flow
	}

	return response, nil
}

func (i *Identifier) handleOAuth2Start(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode oauth 2 start request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request parameters")
		return
	}

	var authority *authorities.Details
	if authorityID := req.Form.Get("authority_id"); authorityID != "" {
		authority, _ = i.authorities.Lookup(req.Context(), authorityID)
	}

	i.newOAuth2Start(rw, req, authority)
}

func (i *Identifier) newOAuth2Start(rw http.ResponseWriter, req *http.Request, authority *authorities.Details) {
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
		i.logger.WithFields(utils.ErrorAsFields(err)).Debugln("oauth2 start error")
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
		i.logger.WithError(err).Errorln("identifier failed to process oauth2 start")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "oauth2 start failed")
		return
	}

	clientID := authority.ClientID
	scopes := authority.Scopes
	responseType := authority.ResponseType
	codeVerifier := rndm.GenerateRandomString(32)
	codeChallengeMethod := authority.CodeChallengeMethod

	sd := &StateData{
		State:    rndm.GenerateRandomString(32),
		RawQuery: req.URL.RawQuery,

		ClientID: clientID,
		Ref:      authority.ID,
	}

	// Construct URL to redirect client to external OAuth2 authorize endpoints.
	uri, _ := url.Parse(authority.AuthorizationEndpoint.String())
	query := make(url.Values)
	query.Add("client_id", clientID)
	if responseType != "" {
		query.Add("response_type", responseType)
	}
	query.Add("response_mode", oidc.ResponseModeQuery)
	query.Add("scope", strings.Join(scopes, " "))
	query.Add("redirect_uri", i.oauth2CbEndpointURI.String())
	query.Add("nonce", rndm.GenerateRandomString(32))
	if codeChallengeMethod != "" {
		if codeChallenge, err := oidc.MakeCodeChallenge(codeChallengeMethod, codeVerifier); err == nil {
			query.Add("code_challenge", codeChallenge)
			query.Add("code_challenge_method", codeChallengeMethod)
		} else {
			i.logger.WithError(err).Debugln("identifier failed to create oauth 2 code challenge")
			i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to create code challenge")
			return
		}
	}
	query.Add("state", sd.State)
	if display := req.Form.Get("display"); display != "" {
		query.Add("display", display)
	}
	if prompt := req.Form.Get("prompt"); prompt != "" {
		query.Add("prompt", prompt)
	}
	if maxAge := req.Form.Get("max_age"); maxAge != "" {
		query.Add("max_age", maxAge)
	}
	if uiLocales := req.Form.Get("ui_locales"); uiLocales != "" {
		query.Add("ui_locales", uiLocales)
	}
	if acrValues := req.Form.Get("acr_values"); acrValues != "" {
		query.Add("acr_values", acrValues)
	}
	if claimsLocales := req.Form.Get("claims_locales"); claimsLocales != "" {
		query.Add("claims_locales", claimsLocales)
	}

	// Set cookie which is consumed by the callback later.
	err = i.SetStateToOAuth2StateCookie(req.Context(), rw, sd)
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to set oauth 2 state cookie")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to set cookie")
		return
	}

	uri.RawQuery = query.Encode()
	utils.WriteRedirect(rw, http.StatusFound, uri, nil, false)
}

func (i *Identifier) handleOAuth2Cb(rw http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		i.logger.WithError(err).Debugln("identifier failed to decode oauth 2 cb request")
		i.ErrorPage(rw, http.StatusBadRequest, "", "failed to decode request parameters")
		return
	}

	i.newOAuth2Cb(rw, req)
}

func (i *Identifier) newOAuth2Cb(rw http.ResponseWriter, req *http.Request) {
	// Callbacks from authorization. Validate as specified at
	// https://tools.ietf.org/html/rfc6749#section-4.1.2 and https://tools.ietf.org/html/rfc6749#section-10.12.
	var err error
	var sd *StateData
	var user *IdentifiedUser
	var claims jwt.MapClaims
	var authority *authorities.Details

	for {
		sd, err = i.GetStateFromOAuth2StateCookie(req.Context(), rw, req)
		if err != nil {
			err = fmt.Errorf("failed to decode oauth2 cb state: %v", err)
			break
		}
		if sd == nil {
			err = errors.New("state not found")
			break
		}

		// Load authority with client_id in state.
		authority, _ = i.authorities.Lookup(req.Context(), sd.Ref)
		if authority == nil {
			i.logger.WithField("client_id", sd.ClientID).Debugln("identifier failed to find authority in oauth2 cb")
			err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2InvalidRequest, "unknown client_id")
			break
		}

		if authenticationErrorID := req.Form.Get("error"); authenticationErrorID != "" {
			// Incoming error case.
			err = konnectoidc.NewOAuth2Error(authenticationErrorID, req.Form.Get("error_description"))
			break
		}

		// Success case.
		authenticationSuccess := &payload.AuthenticationSuccess{}
		err = DecodeURLSchema(authenticationSuccess, req.Form)
		if err != nil {
			err = fmt.Errorf("failed to parse oauth2 cb request: %v", err)
			break
		}

		var username *string
		if authority.AuthorityType == authorities.AuthorityTypeOIDC {
			// Parse and validate IDToken.
			idToken, idTokenParseErr := jwt.ParseWithClaims(authenticationSuccess.IDToken, jwt.MapClaims{}, authority.Keyfunc())
			if idTokenParseErr != nil {
				if authority.Insecure {
					i.logger.WithField("client_id", sd.ClientID).WithError(idTokenParseErr).Warnln("identifier ignoring validation error for insecure authority")
					err = nil
				} else {
					i.logger.WithError(idTokenParseErr).Debugln("identifier failed to validate oauth2 cb id token")
					err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2ServerError, "authority response validation failed")
					break
				}
			}
			claims, _ = idToken.Claims.(jwt.MapClaims)
			if claims == nil {
				err = errors.New("invalid id token claims")
				break
			}

			// Lookup username and user.
			un, claimsErr := authority.IdentityClaimValue(claims)
			if claimsErr != nil {
				i.logger.WithError(claimsErr).Debugln("identifier failed to get username from oauth2 cb id token claims")
				err = konnectoidc.NewOAuth2Error(oidc.ErrorCodeOAuth2InsufficientScope, "identity claim not found")
				break
			}

			username = &un
		} else {
			err = errors.New("unknown authority type")
			break
		}

		user, err = i.resolveUser(req.Context(), *username)
		if err != nil {
			i.logger.WithError(err).WithField("username", *username).Debugln("identifier failed to resolve oauth2 cb user with backend")
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
			i.logger.WithError(err).Debugln("identifier failed to update user data in oauth2 cb request")
		}

		// Set logon time.
		user.logonAt = time.Now()

		err = i.SetUserToLogonCookie(req.Context(), rw, user)
		if err != nil {
			i.logger.WithError(err).Errorln("identifier failed to serialize logon ticket in oauth2 cb")
			i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to serialize logon ticket")
			return
		}

		break
	}

	if sd == nil {
		i.logger.WithError(err).Debugln("identifier oauth2 cb without state")
		i.ErrorPage(rw, http.StatusBadRequest, "", "state not found")
		return
	}

	uri, _ := url.Parse(i.authorizationEndpointURI.String())
	query, _ := url.ParseQuery(sd.RawQuery)
	query.Del("flow")
	query.Set("prompt", oidc.PromptNone)

	switch typedErr := err.(type) {
	case nil:
		// breaks
	case *konnectoidc.OAuth2Error:
		// Pass along OAuth2 error.
		i.logger.WithFields(utils.ErrorAsFields(err)).Debugln("oauth2 cb error")
		// NOTE(longsleep): Pass along error ID but not the description to avoid
		// leaking potetially internal information to our RP.
		query.Set("error", typedErr.ErrorID)
		query.Set("error_description", "identifier failed to authenticate")
		//breaks
	default:
		i.logger.WithError(err).Errorln("identifier failed to process oauth2 cb")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "oauth2 cb failed")
		return
	}

	uri.RawQuery = query.Encode()
	utils.WriteRedirect(rw, http.StatusFound, uri, nil, false)
}
