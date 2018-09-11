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

package identity

import (
	"github.com/dgrijalva/jwt-go"
)

// User defines a most simple user with an id defined as subject.
type User interface {
	Subject() string
}

// UserWithEmail is a User with Email.
type UserWithEmail interface {
	User
	Email() string
	EmailVerified() bool
}

// UserWithProfile is a User with Name.
type UserWithProfile interface {
	User
	Name() string
	FamilyName() string
	GivenName() string
}

// UserWithID is a User with a locally unique numeric id.
type UserWithID interface {
	User
	ID() int64
}

// UserWithUniqueID is a User with a unique string id.
type UserWithUniqueID interface {
	User
	UniqueID() string
}

// UserWithUsername is a User with an username different from subject.
type UserWithUsername interface {
	User
	Username() string
}

// UserWithClaims is a User with jwt claims.
type UserWithClaims interface {
	User
	Claims() jwt.MapClaims
}

// UserWithScopedClaims is a user with jwt claims bound to provided scopes.
type UserWithScopedClaims interface {
	User
	ScopedClaims(authorizedScopes map[string]bool) jwt.MapClaims
}

// UserWithSessionRef is a user which supports an underlaying session reference.
type UserWithSessionRef interface {
	User
	SessionRef() *string
}

// PublicUser is a user with a public Subject and a raw id.
type PublicUser interface {
	Subject() string
	Raw() string
}
