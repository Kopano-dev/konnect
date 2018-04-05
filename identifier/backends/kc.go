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
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/identity"

	"github.com/sirupsen/logrus"
	kcc "stash.kopano.io/kgol/kcc-go"
)

const (
	kcSessionMaxRetries = 3
	kcSessionRetryDelay = 50 * time.Millisecond
)

// KCServerDefaultUsername is the default username used by KCIdentifierBackend
// for KCC when the provided username is empty.
var KCServerDefaultUsername = "SYSTEM"

// Property mappings for Kopano Server user meta data.
var (
	KCServerDefaultFamilyNameProperty = kcc.PR_SURNAME_A
	KCServerDefaultGivenNameProperty  = kcc.PR_GIVEN_NAME_A
)

// KCIdentifierBackend is a backend for the Identifier which connects to
// Kopano Core via kcc-go.
type KCIdentifierBackend struct {
	c        *kcc.KCC
	username string
	password string

	session      *kcc.Session
	sessionMutex sync.RWMutex

	logger logrus.FieldLogger
}

type kcUser struct {
	user *kcc.User
}

func (u *kcUser) Subject() string {
	return u.user.UserEntryID
}

func (u *kcUser) Email() string {
	return u.user.MailAddress
}

func (u *kcUser) EmailVerified() bool {
	return true
}

func (u *kcUser) Name() string {
	return u.user.FullName
}

func (u *kcUser) FamilyName() string {
	var n string
	if u.user.Props != nil {
		n, _ = u.user.Props.Get(KCServerDefaultFamilyNameProperty)
	} else {
		n = u.splitFullName()[1]
	}
	return n
}

func (u *kcUser) GivenName() string {
	var n string
	if u.user.Props != nil {
		n, _ = u.user.Props.Get(KCServerDefaultGivenNameProperty)
	} else {
		n = u.splitFullName()[0]
	}
	return n
}

func (u *kcUser) ID() int64 {
	return int64(u.user.ID)
}

func (u *kcUser) Username() string {
	return u.user.Username
}

func (u *kcUser) splitFullName() [2]string {
	// TODO(longsleep): Cache this, instead of doing every time.
	parts := strings.SplitN(u.user.FullName, " ", 2)
	if len(parts) == 2 {
		return [2]string{parts[0], parts[1]}
	}
	return [2]string{"", ""}
}

// NewKCIdentifierBackend creates a new KCIdentifierBackend with the provided
// parameters.
func NewKCIdentifierBackend(c *config.Config, client *kcc.KCC, username string, password string) (*KCIdentifierBackend, error) {
	if username == "" {
		username = KCServerDefaultUsername
	}

	b := &KCIdentifierBackend{
		c:        client,
		username: username,
		password: password,

		logger: c.Logger,
	}

	b.logger.WithField("client", b.c.String()).Infoln("kc server identifier backend connection set up")

	return b, nil
}

// RunWithContext implements the Backend interface. KCIdentifierBackends keep
// a session to the accociated Kopano Core client. This session is auto renewed
// and auto rerestablished and is bound to the provided Context.
func (b *KCIdentifierBackend) RunWithContext(ctx context.Context) error {
	if b.username != "" {
		b.logger.WithField("username", b.username).Infoln("kc server identifier session enabled")

		go func() {
			retry := time.NewTimer(5 * time.Second)
			retry.Stop()
			refreshCh := make(chan bool, 1)
			for {
				b.setSession(nil)
				session, sessionErr := kcc.NewSession(ctx, b.c, b.username, b.password)
				if sessionErr != nil {
					b.logger.WithError(sessionErr).Errorln("failed to create kc server session")
					retry.Reset(5 * time.Second)
				} else {
					b.logger.Debugf("kc server identifier session established: %v", session)
					b.setSession(session)
					go func() {
						<-session.Context().Done()
						b.logger.Debugf("kc server identifier session has ended: %v", session)
						refreshCh <- true
					}()
				}

				select {
				case <-refreshCh:
					// will retry instantly.
				case <-retry.C:
					// will retry instantly.
				case <-ctx.Done():
					// give up.
					return
				}
			}
		}()
	}

	return nil
}

// Logon implements the Backend interface, enabling Logon with user name and
// password as provided. Requests are bound to the provided context.
func (b *KCIdentifierBackend) Logon(ctx context.Context, username, password string) (bool, *string, error) {
	var logonFlags kcc.KCFlag
	logonFlags |= kcc.KOPANO_LOGON_NO_REGISTER_SESSION | kcc.KOPANO_LOGON_NO_UID_AUTH

	response, err := b.c.Logon(ctx, username, password, logonFlags)
	if err != nil {
		return false, nil, fmt.Errorf("kc identifier backend logon error: %v", err)
	}

	switch response.Er {
	case kcc.KCSuccess:
		// Resolve user details.
		// TODO(longsleep): Avoid extra resolve when logon response already
		// includes the required data (TODO in core).
		resolve, err := b.resolveUsername(ctx, username)
		if err != nil {
			return false, nil, fmt.Errorf("kc identifier backend logon resolve error: %v", err)
		}
		return true, &resolve.UserEntryID, nil

	case kcc.KCERR_LOGON_FAILED:
		return false, nil, nil
	}

	return false, nil, fmt.Errorf("kc identifier backend logon failed: %v", response.Er)
}

// ResolveUser implements the Beckend interface, providing lookup for user by
// providing the username. Requests are bound to the provided context.
func (b *KCIdentifierBackend) ResolveUser(ctx context.Context, username string) (identity.UserWithUsername, error) {
	response, err := b.resolveUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("kc identifier backend resolve user error: %v", err)
	}

	switch response.Er {
	case kcc.KCSuccess:
		// success.

		return &kcUser{
			user: &kcc.User{
				ID:          response.ID,
				Username:    username,
				UserEntryID: response.UserEntryID,
			},
		}, nil

	case kcc.KCERR_NOT_FOUND:
		return nil, nil
	}

	return nil, fmt.Errorf("kc identifier backend get user failed: %v", response.Er)
}

// GetUser implements the Backend interface, providing user meta data retrieval
// for the user specified by the userID. Requests are bound to the provided
// context.
func (b *KCIdentifierBackend) GetUser(ctx context.Context, userID string) (identity.User, error) {
	response, err := b.getUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("kc identifier backend get user error: %v", err)
	}

	switch response.Er {
	case kcc.KCSuccess:
		// success.
		if response.User.UserEntryID != userID {
			return nil, fmt.Errorf("kc identifier backend get user returned wrong user")
		}

		return &kcUser{
			user: response.User,
		}, nil

	case kcc.KCERR_NOT_FOUND:
		return nil, nil
	}

	return nil, fmt.Errorf("kc identifier backend get user failed: %v", response.Er)
}

func (b *KCIdentifierBackend) resolveUsername(ctx context.Context, username string) (*kcc.ResolveUserResponse, error) {
	result, err := b.withSessionAndRetry(ctx, func(ctx context.Context, session *kcc.Session) (interface{}, error, bool) {
		user, err := b.c.ResolveUsername(ctx, username, session.ID())
		if err != nil {
			return nil, err, true
		}

		if user.Er == kcc.KCERR_NOT_FOUND {
			return nil, user.Er, false
		}

		return user, nil, true
	})
	if err != nil {
		return nil, err
	}

	user := result.(*kcc.ResolveUserResponse)
	return user, err
}

func (b *KCIdentifierBackend) getUser(ctx context.Context, userEntryID string) (*kcc.GetUserResponse, error) {
	result, err := b.withSessionAndRetry(ctx, func(ctx context.Context, session *kcc.Session) (interface{}, error, bool) {
		user, err := b.c.GetUser(ctx, userEntryID, session.ID())
		if err != nil {
			return nil, err, true
		}

		if user.Er == kcc.KCERR_NOT_FOUND {
			return nil, user.Er, false
		}

		return user, nil, true
	})
	if err != nil {
		return nil, err
	}

	user := result.(*kcc.GetUserResponse)
	return user, err
}

func (b *KCIdentifierBackend) withSessionAndRetry(ctx context.Context, worker func(context.Context, *kcc.Session) (interface{}, error, bool)) (interface{}, error) {
	retries := 0
	for {
		session := b.getSession()
		if session == nil || !session.IsActive() {
			return nil, fmt.Errorf("no server session")
		}

		var failedErr error
		for {
			result, err, shouldRetry := worker(ctx, session)
			if err != nil {
				if !shouldRetry {
					return result, err
				}

				failedErr = err
				break
			}

			// NOTE(longsleep): This is pretty crappy - is there a better way?
			kcErr := reflect.ValueOf(result).Elem().FieldByName("Er").Interface().(kcc.KCError)
			if kcErr != kcc.KCSuccess {
				if !shouldRetry {
					return result, kcErr
				}

				failedErr = kcErr
				break
			}

			return result, nil
		}

		if failedErr != nil {
			switch failedErr {
			case kcc.KCERR_END_OF_SESSION:
				session.Destroy(ctx, false)
			default:
				return nil, failedErr
			}
		}

		// If reach here, its a retry.
		select {
		case <-time.After(kcSessionRetryDelay):
			// Retry now.
		case <-ctx.Done():
			// Abort.
			return nil, ctx.Err()
		}

		retries++
		if retries > kcSessionMaxRetries {
			b.logger.WithField("retry", retries).Errorln("kc identifier backend giving up kc request")
			return nil, failedErr
		}
		b.logger.WithField("retry", retries).Debugln("kc identifier backend retry in progress")
	}
}

func (b *KCIdentifierBackend) setSession(session *kcc.Session) {
	b.sessionMutex.Lock()
	b.session = session
	b.sessionMutex.Unlock()
}

func (b *KCIdentifierBackend) getSession() *kcc.Session {
	b.sessionMutex.RLock()
	session := b.session
	b.sessionMutex.RUnlock()
	return session
}
