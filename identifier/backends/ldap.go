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

package backends

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/identity"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
	"gopkg.in/ldap.v2"
)

// LDAPIdentifierBackend is a backend for the Identifier which connects LDAP.
type LDAPIdentifierBackend struct {
	addr         string
	isTLS        bool
	bindDN       string
	bindPassword string

	baseDN       string
	scope        int
	searchFilter string
	getFilter    string

	attributeMapping *ldapAttributeMapping

	logger    logrus.FieldLogger
	dialer    *net.Dialer
	tlsConfig *tls.Config

	timeout int
	limiter *rate.Limiter
}

type ldapAttributeMapping struct {
	login string
	email string
	name  string
}

type ldapUser struct {
	mapping *ldapAttributeMapping
	entry   *ldap.Entry
}

func (u *ldapUser) getAttributeValue(n string) string {
	if n == "" {
		return ""
	}
	return u.entry.GetAttributeValue(n)
}

func (u *ldapUser) Subject() string {
	return u.entry.DN
}

func (u *ldapUser) Email() string {
	return u.getAttributeValue(u.mapping.email)
}

func (u *ldapUser) EmailVerified() bool {
	return false
}

func (u *ldapUser) Name() string {
	return u.getAttributeValue(u.mapping.name)
}

func (u *ldapUser) Username() string {
	return u.getAttributeValue(u.mapping.login)
}

// NewLDAPIdentifierBackend creates a new LDAPIdentifierBackend with the provided
// parameters.
func NewLDAPIdentifierBackend(
	c *config.Config,
	tlsConfig *tls.Config,
	uriString,
	bindDN,
	bindPassword,
	baseDN,
	scopeString,
	loginAttribute,
	emailAttribute,
	nameAttribute,
	filter string,
) (*LDAPIdentifierBackend, error) {
	var err error
	var scope int
	var uri *url.URL
	for {
		if uriString == "" {
			err = fmt.Errorf("server must not be empty")
			break
		}
		uri, err = url.Parse(uriString)
		if err != nil {
			break
		}

		if bindDN == "" && bindPassword != "" {
			err = fmt.Errorf("bind DN must not be empty when bind password is given")
			break
		}
		if baseDN == "" {
			err = fmt.Errorf("base DN must not be empty")
			break
		}
		switch scopeString {
		case "sub":
			scope = ldap.ScopeWholeSubtree
		case "one":
			scope = ldap.ScopeSingleLevel
		case "base":
			scope = ldap.ScopeBaseObject
		case "":
			scope = ldap.ScopeWholeSubtree
		default:
			err = fmt.Errorf("unknown scope value: %v, must be one of sub, one or base", scopeString)
		}
		if err != nil {
			break
		}

		break
	}
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend %v", err)
	}

	if loginAttribute == "" {
		loginAttribute = "uid"
	}
	if emailAttribute == "" {
		emailAttribute = "mail"
	}
	if nameAttribute == "" {
		nameAttribute = "cn"
	}
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}

	addr := uri.Host
	isTLS := false

	switch uri.Scheme {
	case "":
		uri.Scheme = "ldap"
		fallthrough
	case "ldap":
		if uri.Port() == "" {
			addr += ":389"
		}
	case "ldaps":
		if uri.Port() == "" {
			addr += ":636"
		}
		isTLS = true
	default:
		err = fmt.Errorf("invalid URI scheme: %v", uri.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend %v", err)
	}

	b := &LDAPIdentifierBackend{
		addr:         addr,
		isTLS:        isTLS,
		bindDN:       bindDN,
		bindPassword: bindPassword,
		baseDN:       baseDN,
		scope:        scope,
		searchFilter: fmt.Sprintf("(&(%s)(%s=%%s))", filter, loginAttribute),
		getFilter:    filter,

		attributeMapping: &ldapAttributeMapping{
			login: loginAttribute,
			email: emailAttribute,
			name:  nameAttribute,
		},

		logger: c.Logger,
		dialer: &net.Dialer{
			Timeout:   ldap.DefaultTimeout,
			DualStack: true,
		},
		tlsConfig: tlsConfig,

		timeout: 60,                        //XXX(longsleep): make timeout configuration.
		limiter: rate.NewLimiter(100, 200), //XXX(longsleep): make rate limits configuration.
	}

	b.logger.WithField("ldap", fmt.Sprintf("%s://%s ", uri.Scheme, addr)).Infoln("ldap server identifier backend set up")

	return b, nil
}

// RunWithContext implements the Backend interface.
func (b *LDAPIdentifierBackend) RunWithContext(ctx context.Context) error {
	return nil
}

// Logon implements the Backend interface, enabling Logon with user name and
// password as provided. Requests are bound to the provided context.
func (b *LDAPIdentifierBackend) Logon(ctx context.Context, username, password string) (bool, *string, error) {
	l, err := b.connect(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("ldap identifier backend logon connect error: %v", err)
	}
	defer l.Close()

	// Search for the given username.
	entry, err := b.searchUsername(l, username, []string{"dn", b.attributeMapping.login})
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("ldap identifier backend logon search error: %v", err)
	}
	if entry.GetAttributeValue(b.attributeMapping.login) != username {
		return false, nil, fmt.Errorf("ldap identifier backend logon search returned wrong user")
	}

	userDN := entry.DN

	// Bind as the user to verify the password.
	err = l.Bind(userDN, password)
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return false, nil, nil
	}

	if err != nil {
		return false, nil, fmt.Errorf("ldap identifier backend logon error: %v", err)
	}

	return true, &userDN, nil
}

// ResolveUser implements the Beckend interface, providing lookup for user by
// providing the username. Requests are bound to the provided context.
func (b *LDAPIdentifierBackend) ResolveUser(ctx context.Context, username string) (identity.UserWithUsername, error) {
	l, err := b.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend resolve connect error: %v", err)
	}
	defer l.Close()

	// Search for the given username.
	entry, err := b.searchUsername(l, username, []string{"dn", b.attributeMapping.login})
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend resolve search error: %v", err)
	}
	if entry.GetAttributeValue(b.attributeMapping.login) != username {
		return nil, fmt.Errorf("ldap identifier backend resolve search returned wrong user")
	}

	return &ldapUser{
		mapping: b.attributeMapping,
		entry:   entry,
	}, nil
}

// GetUser implements the Backend interface, providing user meta data retrieval
// for the user specified by the useID. Requests are bound to the provided
// context.
func (b *LDAPIdentifierBackend) GetUser(ctx context.Context, userID string) (identity.User, error) {
	_, err := ldap.ParseDN(userID)
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend get user invalid user ID: %v", err)
	}

	l, err := b.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend get user connect error: %v", err)
	}
	defer l.Close()

	entry, err := b.getUser(l, userID, nil)
	if err != nil {
		return nil, fmt.Errorf("ldap identifier backend get user error: %v", err)
	}
	if entry.DN != userID {
		return nil, fmt.Errorf("ldap identifier backend get user returned wrong user")
	}

	return &ldapUser{
		mapping: b.attributeMapping,
		entry:   entry,
	}, nil
}

func (b *LDAPIdentifierBackend) connect(parentCtx context.Context) (*ldap.Conn, error) {
	// A timeout for waiting for a limiter slot. The timeout also includes the
	// time to connect to the LDAP server which as a consequence means that both
	// getting a free slot and establishing the connection are one timeout.
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(b.timeout)*time.Second)
	defer cancel()

	err := b.limiter.Wait(ctx)
	if err != nil {
		return nil, err
	}

	c, err := b.dialer.DialContext(ctx, "tcp", b.addr)
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	var l *ldap.Conn
	if b.isTLS {
		sc := tls.Client(c, b.tlsConfig)
		err = sc.Handshake()
		if err != nil {
			c.Close()
			return nil, ldap.NewError(ldap.ErrorNetwork, err)
		}
		l = ldap.NewConn(sc, true)

	} else {
		l = ldap.NewConn(c, false)
	}

	l.Start()

	// Bind with general user (which is preferably read only).
	if b.bindDN != "" {
		err = l.Bind(b.bindDN, b.bindPassword)
		if err != nil {
			return nil, err
		}
	}

	return l, nil
}

func (b *LDAPIdentifierBackend) searchUsername(l *ldap.Conn, username string, attributes []string) (*ldap.Entry, error) {
	// Search for the given username.
	searchRequest := ldap.NewSearchRequest(
		b.baseDN,
		b.scope, ldap.NeverDerefAliases, 1, b.timeout, false,
		fmt.Sprintf(b.searchFilter, username),
		attributes,
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	switch len(sr.Entries) {
	case 0:
		// Nothing found.
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, err)
	case 1:
		// Exactly one found, success.
		return sr.Entries[0], nil
	default:
		// Invalid when multiple matched.
		return nil, fmt.Errorf("user too many entries returned")
	}
}

func (b *LDAPIdentifierBackend) getUser(l *ldap.Conn, userDN string, attributes []string) (*ldap.Entry, error) {
	// search for the given DN.
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, b.timeout, false,
		b.getFilter,
		attributes,
		nil,
	)
	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) != 1 {
		return nil, fmt.Errorf("user does not exist or too many entries returned")
	}

	return sr.Entries[0], nil
}
