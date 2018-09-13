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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/identifier/backends"
	"stash.kopano.io/kc/konnect/identifier/clients"
	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/managers"
	"stash.kopano.io/kc/konnect/utils"
)

// Identifier defines a identification login area with its endpoints using
// a Kopano Core server as backend logon provider.
type Identifier struct {
	Config *Config

	pathPrefix      string
	staticFolder    string
	logonCookieName string
	webappIndexHTML []byte

	authorizationEndpointURI *url.URL

	encrypter jose.Encrypter
	recipient *jose.Recipient
	backend   backends.Backend
	clients   *clients.Registry

	onSetLogonCallbacks   []func(ctx context.Context, rw http.ResponseWriter, user identity.User) error
	onUnsetLogonCallbacks []func(ctx context.Context, rw http.ResponseWriter) error

	logger logrus.FieldLogger
}

// NewIdentifier returns a new Identifier.
func NewIdentifier(c *Config) (*Identifier, error) {
	staticFolder := c.StaticFolder
	webappIndexHTMLFilename := staticFolder + "/index.html"
	if _, err := os.Stat(webappIndexHTMLFilename); os.IsNotExist(err) {
		return nil, fmt.Errorf("identifier static client files: %v", err)
	}
	webappIndexHTML, err := ioutil.ReadFile(webappIndexHTMLFilename)
	if err != nil {
		return nil, fmt.Errorf("identifier failed to read client index.html: %v", err)
	}

	i := &Identifier{
		Config: c,

		pathPrefix:      c.PathPrefix,
		staticFolder:    staticFolder,
		logonCookieName: c.LogonCookieName,
		webappIndexHTML: webappIndexHTML,

		authorizationEndpointURI: c.AuthorizationEndpointURI,

		backend: c.Backend,

		onSetLogonCallbacks:   make([]func(ctx context.Context, rw http.ResponseWriter, user identity.User) error, 0),
		onUnsetLogonCallbacks: make([]func(ctx context.Context, rw http.ResponseWriter) error, 0),

		logger: c.Config.Logger,
	}

	return i, nil
}

// RegisterManagers registers the provided managers,
func (i *Identifier) RegisterManagers(mgrs *managers.Managers) error {
	i.clients = mgrs.Must("clients").(*clients.Registry)

	if service, ok := i.backend.(managers.ServiceUsesManagers); ok {
		err := service.RegisterManagers(mgrs)
		if err != nil {
			return err
		}
	}

	return nil
}

// AddRoutes adds the endpoint routes of the accociated Identifier to the
// provided router with the provided context.
func (i *Identifier) AddRoutes(ctx context.Context, router *mux.Router) {
	r := router.PathPrefix(i.pathPrefix).Subrouter()

	r.PathPrefix("/static/").Handler(i.staticHandler(http.StripPrefix(i.pathPrefix, http.FileServer(http.Dir(i.staticFolder))), true))
	r.Handle("/service-worker.js", i.staticHandler(http.StripPrefix(i.pathPrefix, http.FileServer(http.Dir(i.staticFolder))), false))
	r.Handle("/identifier", i).Methods(http.MethodGet)
	r.Handle("/chooseaccount", i).Methods(http.MethodGet)
	r.Handle("/consent", i).Methods(http.MethodGet)
	r.Handle("/welcome", i).Methods(http.MethodGet)
	r.Handle("/goodbye", i).Methods(http.MethodGet)
	r.Handle("/index.html", i).Methods(http.MethodGet) // For service worker.
	r.Handle("/identifier/_/logon", i.secureHandler(http.HandlerFunc(i.handleLogon))).Methods(http.MethodPost)
	r.Handle("/identifier/_/logoff", i.secureHandler(http.HandlerFunc(i.handleLogoff))).Methods(http.MethodPost)
	r.Handle("/identifier/_/hello", i.secureHandler(http.HandlerFunc(i.handleHello))).Methods(http.MethodPost)
	r.Handle("/identifier/_/consent", i.secureHandler(http.HandlerFunc(i.handleConsent))).Methods(http.MethodPost)

	if i.backend != nil {
		i.backend.RunWithContext(ctx)
	}
}

// ServeHTTP implements the http.Handler interface.
func (i *Identifier) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	addCommonResponseHeaders(rw.Header())

	nonce := rndm.GenerateRandomString(32)

	rw.Header().Set("Cache-Control", "no-cache, max-age=0, public")
	// FIXME(longsleep): Set a secure CSP. Right now we need `data:` for images
	// since it is used. Since `data:` URLs possibly could allow xss, a better
	// way should be found for our early loading inline SVG stuff.
	rw.Header().Set("Content-Security-Policy", fmt.Sprintf("default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'nonce-%s'; base-uri 'none'; frame-ancestors 'none';", nonce))

	// Inject random nonce.
	index := bytes.Replace(i.webappIndexHTML, []byte("__CSP_NONCE__"), []byte(nonce), 1)
	rw.Write(index)
}

// SetKey sets the provided key for the accociated identifier.
func (i *Identifier) SetKey(key []byte) error {
	var ce jose.ContentEncryption
	var algo jose.KeyAlgorithm
	switch len(key) {
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
		return fmt.Errorf("identifier invalid encryption key size. Need 16, 24 or 32 bytes")
	}

	if len(key) < 32 {
		i.logger.Warnf("identifier using encryption key size with %d bytes which is below 32 bytes", len(key))
	} else {
		i.logger.WithField("security", fmt.Sprintf("%s:%s", ce, algo)).Infoln("identifier set up")
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

// SetUserToLogonCookie serializes the provided user into an encrypted string
// and sets it as cookie on the provided http.ResponseWriter.
func (i *Identifier) SetUserToLogonCookie(ctx context.Context, rw http.ResponseWriter, user *IdentifiedUser) error {
	loggedOn, logonAt := user.LoggedOn()
	if !loggedOn {
		return fmt.Errorf("refused to set cookie for not logged on user")
	}

	// Encrypt cookie value.
	claims := jwt.Claims{
		Subject:  user.Subject(),
		IssuedAt: jwt.NewNumericDate(logonAt),
	}

	userClaims := map[string]interface{}(user.Claims())
	sessionRef := user.SessionRef()
	if sessionRef != nil {
		userClaims[SessionIDClaim] = user.SessionRef()
	}
	serialized, err := jwt.Encrypted(i.encrypter).Claims(claims).Claims(userClaims).CompactSerialize()
	if err != nil {
		return err
	}

	// Set cookie.
	err = i.setLogonCookie(rw, serialized)
	if err != nil {
		return err
	}
	// Trigger callbacks.
	for _, f := range i.onSetLogonCallbacks {
		err = f(ctx, rw, user)
		if err != nil {
			return err
		}
	}

	return nil
}

// UnsetLogonCookie adds cookie remove headers to the provided http.ResponseWriter
// effectively implementing logout.
func (i *Identifier) UnsetLogonCookie(ctx context.Context, user *IdentifiedUser, rw http.ResponseWriter) error {
	// Remove cookie.
	err := i.removeLogonCookie(rw)
	if err != nil {
		return err
	}
	// Destroy backend user session if any.
	sessionRef := user.SessionRef()
	if user != nil && sessionRef != nil {
		err = i.backend.DestroySession(ctx, sessionRef)
		if err != nil {
			i.logger.WithError(err).Warnln("failed to destroy session on unset logon cookie")
		}
	}
	// Trigger callbacks.
	for _, f := range i.onUnsetLogonCallbacks {
		err = f(ctx, rw)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetUserFromLogonCookie looks up the associated cookie name from the provided
// request, parses it and returns the user containing the information found in
// the coookie payload data.
func (i *Identifier) GetUserFromLogonCookie(ctx context.Context, req *http.Request, maxAge time.Duration, refreshSession bool) (*IdentifiedUser, error) {
	cookie, err := i.getLogonCookie(req)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil
		}
		return nil, err
	}

	token, err := jwt.ParseEncrypted(cookie.Value)
	if err != nil {
		return nil, err
	}

	var claims jwt.Claims
	var userClaims map[string]interface{}
	if err = token.Claims(i.recipient.Key, &claims, &userClaims); err != nil {
		return nil, err
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("invalid subject in logon token")
	}
	if userClaims == nil {
		return nil, fmt.Errorf("invalid user claims in logon token")
	}

	user := &IdentifiedUser{
		sub: claims.Subject,

		// TODO(longsleep): It is not verified here that the user still exists at
		// our current backend. We still assign the backend happily here - probably
		// needs some sort of veritification / lookup.
		backend: i.backend,

		logonAt: claims.IssuedAt.Time(),
	}

	loggedOn, logonAt := user.LoggedOn()
	if !loggedOn {
		// Ignore logons which are not valid.
		return nil, nil
	}
	if maxAge > 0 {
		if logonAt.Add(maxAge).Before(time.Now()) {
			// Ignore logon as it is no longer valid within maxAge.
			return nil, nil
		}
	}

	if v, _ := userClaims[SessionIDClaim]; v != nil {
		sessionRef := v.(string)
		if sessionRef != "" {
			// Remember session ref in user.
			user.sessionRef = &sessionRef
			// Ensure the session is still valid, by refreshing it.
			if refreshSession {
				err = i.backend.RefreshSession(ctx, user.Subject(), &sessionRef)
				if err != nil {
					// Ignore logons which fail session refresh.
					return nil, nil
				}
			}
		}
	}

	if v, _ := userClaims[konnect.IdentifiedUsernameClaim]; v != nil {
		user.username = v.(string)
	}
	if v, _ := userClaims[konnect.IdentifiedDisplayNameClaim]; v != nil {
		user.displayName = v.(string)
	}

	return user, nil
}

// GetUserFromID looks up the user identified by the provided subject by
// requesting the associated backend.
func (i *Identifier) GetUserFromID(ctx context.Context, sub string, sessionRef *string) (*IdentifiedUser, error) {
	user, err := i.backend.GetUser(ctx, sub, sessionRef)
	if err != nil {
		return nil, err
	}

	// XXX(longsleep): This is quite crappy. Move IdentifiedUser to a package
	// which can be imported by backends so they directly can return that shit.
	identifiedUser := &IdentifiedUser{
		sub: user.Subject(),

		backend: i.backend,

		sessionRef: sessionRef,
	}
	if userWithEmail, ok := user.(identity.UserWithEmail); ok {
		identifiedUser.email = userWithEmail.Email()
		identifiedUser.emailVerified = userWithEmail.EmailVerified()
	}
	if userWithProfile, ok := user.(identity.UserWithProfile); ok {
		identifiedUser.displayName = userWithProfile.Name()
		identifiedUser.familyName = userWithProfile.FamilyName()
		identifiedUser.givenName = userWithProfile.GivenName()
	}
	if userWithID, ok := user.(identity.UserWithID); ok {
		identifiedUser.id = userWithID.ID()
	}
	if userWithUniqueID, ok := user.(identity.UserWithUniqueID); ok {
		identifiedUser.uid = userWithUniqueID.UniqueID()
	}
	if userWithUsername, ok := user.(identity.UserWithUsername); ok {
		identifiedUser.username = userWithUsername.Username()
	}

	return identifiedUser, nil
}

// SetConsentToConsentCookie serializses the provided Consent using the provided
// ConsentRequest and sets it as cookie on the provided ReponseWriter.
func (i *Identifier) SetConsentToConsentCookie(ctx context.Context, rw http.ResponseWriter, cr *ConsentRequest, consent *Consent) error {
	serialized, err := jwt.Encrypted(i.encrypter).Claims(consent).CompactSerialize()
	if err != nil {
		return err
	}

	return i.setConsentCookie(rw, cr, serialized)
}

// GetConsentFromConsentCookie extract consent information for the provided
// request.
func (i *Identifier) GetConsentFromConsentCookie(ctx context.Context, rw http.ResponseWriter, req *http.Request) (*Consent, error) {
	state := req.Form.Get("konnect")
	if state == "" {
		return nil, nil
	}

	cr := &ConsentRequest{
		State:          state,
		ClientID:       req.Form.Get("client_id"),
		RawRedirectURI: req.Form.Get("redirect_uri"),
		Ref:            req.Form.Get("state"),
		Nonce:          req.Form.Get("nonce"),
	}

	cookie, err := i.getConsentCookie(req, cr)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil
		}
		return nil, err
	}

	// Directly remove the cookie again after we used it.
	i.removeConsentCookie(rw, req, cr)

	token, err := jwt.ParseEncrypted(cookie.Value)
	if err != nil {
		return nil, err
	}

	var consent Consent
	if err = token.Claims(i.recipient.Key, &consent); err != nil {
		return nil, err
	}

	return &consent, nil
}

// Name returns the active identifiers backend's name.
func (i *Identifier) Name() string {
	return i.backend.Name()
}

// ScopesSupported return the scopes supported by the accociaged Identifier.
func (i *Identifier) ScopesSupported() []string {
	return i.backend.ScopesSupported()
}

// OnSetLogon implements a way to register hooks whenever logon information is
// set by the accociated Identifier.
func (i *Identifier) OnSetLogon(cb func(ctx context.Context, rw http.ResponseWriter, user identity.User) error) error {
	i.onSetLogonCallbacks = append(i.onSetLogonCallbacks, cb)
	return nil
}

// OnUnsetLogon implements a way to register hooks whenever logon information is
// set by the accociated Identifier.
func (i *Identifier) OnUnsetLogon(cb func(ctx context.Context, rw http.ResponseWriter) error) error {
	i.onUnsetLogonCallbacks = append(i.onUnsetLogonCallbacks, cb)
	return nil
}
