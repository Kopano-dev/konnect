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
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"stash.kopano.io/kc/konnect/identifier/backends"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/utils"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
)

// Identifier defines a identification login area with its endpoints using
// a Kopano Core server as backend logon provider.
type Identifier struct {
	Config *Config

	uriPrefix       string
	staticFolder    string
	logonCookieName string

	encrypter jose.Encrypter
	recipient *jose.Recipient
	backend   backends.Backend

	logger logrus.FieldLogger
}

// NewIdentifier returns a new Identifier.
func NewIdentifier(c *Config) (*Identifier, error) {
	i := &Identifier{
		Config: c,

		uriPrefix:       "/signin/v1",
		staticFolder:    "./identifier/build",
		logonCookieName: "__Secure-KKT", // Kopano-Konnect-Token

		backend: c.Backend,
		logger:  c.Config.Logger,
	}

	return i, nil
}

// AddRoutes adds the endpoint routes of the accociated Identifier to the
// provided router with the provided context.
func (i *Identifier) AddRoutes(ctx context.Context, router *mux.Router) {
	r := router.PathPrefix(i.uriPrefix).Subrouter()

	r.PathPrefix("/static/").Handler(i.staticHandler(http.StripPrefix(i.uriPrefix, http.FileServer(http.Dir(i.staticFolder))), true))
	r.Handle("/service-worker.js", i.staticHandler(http.StripPrefix(i.uriPrefix, http.FileServer(http.Dir(i.staticFolder))), false))
	r.Handle("/identifier", i).Methods(http.MethodGet)
	r.Handle("/identifier/_/logon", i.secureHandler(http.HandlerFunc(i.handleLogon))).Methods(http.MethodPost)
	r.Handle("/identifier/_/hello", i.secureHandler(http.HandlerFunc(i.handleHello))).Methods(http.MethodPost)

	if i.backend != nil {
		i.backend.RunWithContext(ctx)
	}
}

// ServeHTTP implements the http.Handler interface.
func (i *Identifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	i.addCommonResponseHeaders(rw.Header())
	rw.Header().Set("Cache-Control", "no-cache, max-age=0, public")

	http.ServeFile(rw, req, i.staticFolder+"/index.html")
}

// SetKey sets the provided key for the accociated identifier.
func (i *Identifier) SetKey(key []byte) error {
	var ce jose.ContentEncryption
	var algo jose.KeyAlgorithm
	switch hex.DecodedLen(len(key)) {
	case 16:
		ce = jose.A128GCM
		algo = jose.A128GCMKW
	case 24:
		ce = jose.A192GCM
		algo = jose.A192GCMKW
	case 32:
		ce = jose.A256GCM
		algo = jose.A256GCMKW
	default:
		return fmt.Errorf("identifier: invalid encryption key size. Need hex encded 128, 192 or 256 bytes")
	}

	dst := make([]byte, hex.DecodedLen(len(key)))
	if _, err := hex.Decode(dst, key); err == nil {
		key = dst
	} else {
		return fmt.Errorf("identifier: failed to hex decode encryption key: %v", err)
	}

	if len(key) < 32 {
		i.logger.Warnf("using encryption key size with %d bytes which is below 32 bytes", len(key))
	}

	recipient := jose.Recipient{
		Algorithm: algo,
		KeyID:     "",
		Key:       key,
	}
	encrypter, err := jose.NewEncrypter(
		ce,
		recipient,
		nil,
	)
	if err != nil {
		return err
	}

	i.encrypter = encrypter
	i.recipient = &recipient
	return nil
}

// ErrorPage writes a HTML error page to the provided ResponseWriter.
func (i *Identifier) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	utils.WriteErrorPage(rw, code, title, message)
}

func (i *Identifier) staticHandler(handler http.Handler, cache bool) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		i.addCommonResponseHeaders(rw.Header())
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

		// This follows https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet
		for {
			if req.Header.Get("Kopano-Konnect-XSRF") != "1" {
				err = fmt.Errorf("missing xsrf header")
				break
			}

			origin := req.Header.Get("Origin")

			// Require both Origin and Referer header.
			if origin == "" || req.Header.Get("Referer") == "" {
				err = fmt.Errorf("missing origin or referer header")
				break
			}

			originURL, urlParseErr := url.Parse(origin)
			if urlParseErr != nil {
				err = fmt.Errorf("invalid origin value: %v", urlParseErr)
				break
			}

			// Require request.Host to be the same as in originURL
			// TODO(longsleep): Add support for X-Forwareded-Host with trusted proxy.
			if req.Host != originURL.Host {
				err = fmt.Errorf("origin does not match request URL")
				break
			}

			handler.ServeHTTP(rw, req)
			return
		}

		if err != nil {
			i.logger.WithError(err).WithFields(logrus.Fields{
				"host":       req.Host,
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

	i.addNoCacheResponseHeaders(rw.Header())

	params := r.Params
	for {
		// Check frontend proxy injected auth (Eg. Kerberos/NTLM).
		forwardedUser := req.Header.Get("X-Forwarded-User")
		if forwardedUser != "" {
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
			// Empty password.
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

	i.addNoCacheResponseHeaders(rw.Header())

	for {
		if r.Prompt {
			// Ignore all potential sources, when prompt was requested.
			break
		}

		// Check if logged in via cookie.
		// TODO(longsleep): Implement cookie load and validate.

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

func (i *Identifier) addCommonResponseHeaders(header http.Header) {
	header.Set("X-Frame-Options", "DENY")
	header.Set("X-XSS-Protection", "1; mode=block")
	header.Set("X-Content-Type-Options", "nosniff")
}

func (i *Identifier) addNoCacheResponseHeaders(header http.Header) {
	header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	header.Set("Pragma", "no-cache")
	header.Set("Expires", "0")
}

func (i *Identifier) setLogonCookie(rw http.ResponseWriter, user *IdentifiedUser) error {
	// Encrypt cookie value.
	claims := jwt.Claims{
		Subject: user.Subject(),
	}
	serialized, err := jwt.Encrypted(i.encrypter).Claims(claims).CompactSerialize()
	if err != nil {
		return err
	}

	cookie := http.Cookie{
		Name:  i.logonCookieName,
		Value: serialized,

		Path:     i.uriPrefix + "/identifier/_/",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(rw, &cookie)

	return nil
}

func (i *Identifier) GetUserFromLogonCookie(ctx context.Context, req *http.Request) (*IdentifiedUser, error) {
	cookie, err := req.Cookie(i.logonCookieName)
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseEncrypted(cookie.Value)
	if err != nil {
		return nil, err
	}

	var claims jwt.Claims
	if err = token.Claims(i.recipient.Key, &claims); err != nil {
		return nil, err
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("invalid subject in logon token")
	}

	return &IdentifiedUser{
		sub: claims.Subject,
	}, nil
}

func (i *Identifier) GetUserFromSubject(ctx context.Context, sub string) (*IdentifiedUser, error) {
	user, err := i.backend.GetUser(ctx, sub)
	if err != nil {
		return nil, err
	}

	// XXX(longsleep): This is quite crappy. Move IdentifiedUser to a package
	// which can be imported by backends so they directly can return that shit.
	identifiedUser := &IdentifiedUser{
		sub: user.Subject(),
	}
	if userWithEmail, ok := user.(identity.UserWithEmail); ok {
		identifiedUser.email = userWithEmail.Email()
		identifiedUser.emailVerified = userWithEmail.EmailVerified()
	}
	if userWithProfile, ok := user.(identity.UserWithProfile); ok {
		identifiedUser.displayName = userWithProfile.Name()
	}
	if userWithID, ok := user.(identity.UserWithID); ok {
		identifiedUser.id = userWithID.ID()
	}
	if userWithUsername, ok := user.(identity.UserWithUsername); ok {
		identifiedUser.username = userWithUsername.Username()
	}

	return identifiedUser, nil
}
