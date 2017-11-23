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

package identifier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sirupsen/logrus"

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

	params := r.Params
	// Params is an array like this [$username, $password, $mode].
	for {
		if len(params) >= 3 && params[1] == "" && params[2] == "1" {
			// Check if same user is logged in via cookie.
			identifiedUser, cookieErr := i.GetUserFromLogonCookie(req.Context(), req)
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

		forwardedUser := req.Header.Get("X-Forwarded-User")
		if forwardedUser != "" {
			// Check frontend proxy injected auth (Eg. Kerberos/NTLM).
			if len(params) >= 1 && forwardedUser == params[0] {
				u, resolveErr := i.backend.ResolveUser(req.Context(), params[0])
				if resolveErr != nil {
					i.logger.WithError(resolveErr).Errorln("identifier failed to resolve user with backend")
					i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to resolve user")
					return
				}

				// Construct user from resolved result.
				user = &IdentifiedUser{
					sub:      u.Subject(),
					username: u.Username(),
				}
			}
			break
		}

		if len(params) >= 2 && params[1] == "" {
			// Empty password, stop here.
			break
		}

		if len(params) >= 3 && params[2] == "1" {
			// Username and password.
			var success bool
			var subject *string
			success, subject, err = i.backend.Logon(req.Context(), params[0], params[1])
			if err != nil {
				i.logger.WithError(err).Errorln("identifier failed to logon with backend")
				i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to logon")
				return
			}
			if success {
				// Construct user from logon result.
				user = &IdentifiedUser{
					sub:      *subject,
					username: params[0],
				}
			}
			break
		}

		break
	}

	if user == nil || user.Subject() == "" {
		rw.Header().Set("Kopano-Konnect-State", response.State)
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	err = i.setLogonCookie(rw, user)
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

	err = i.removeLogonCookie(rw)
	if err != nil {
		i.logger.WithError(err).Errorln("identifier failed to set logoff ticket")
		i.ErrorPage(rw, http.StatusInternalServerError, "", "failed to set logoff ticket")
		return
	}

	response := &StateResponse{
		State:   r.State,
		Success: true,
	}

	rw.WriteHeader(http.StatusOK)

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

	response := &HelloResponse{
		State: r.State,
	}

	addNoCacheResponseHeaders(rw.Header())

	for {
		if r.Prompt {
			// Ignore all potential sources, when prompt was requested.
			break
		}

		// Check if logged in via cookie.
		identifiedUser, cookieErr := i.GetUserFromLogonCookie(req.Context(), req)
		if cookieErr != nil {
			i.logger.WithError(cookieErr).Debugln("identifier failed to decode logon cookie in hello request")
		}
		if identifiedUser != nil {
			response.Username = identifiedUser.Username()
			if response.Username != "" {
				response.Success = true
				break
			}
		}

		// Check frontend proxy injected auth (Eg. Kerberos/NTLM).
		forwardedUser := req.Header.Get("X-Forwarded-User")
		if forwardedUser != "" {
			response.Username = forwardedUser
			response.Success = true
			break
		}

		break
	}
	if !response.Success {
		rw.Header().Set("Kopano-Konnect-State", response.State)
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	rw.WriteHeader(http.StatusOK)

	err = utils.WriteJSON(rw, http.StatusOK, response, "")
	if err != nil {
		i.logger.WithError(err).Errorln("hello request failed writing response")
	}
}
