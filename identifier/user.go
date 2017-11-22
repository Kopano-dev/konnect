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

// A IdentifiedUser is a user with meta data.
type IdentifiedUser struct {
	sub string

	username      string
	email         string
	emailVerified bool
	displayName   string

	id int64
}

// Subject returns the associated users subject field. The subject is the main
// authentication identifier of the user.
func (u *IdentifiedUser) Subject() string {
	return u.sub
}

// Email returns the associated users email field.
func (u *IdentifiedUser) Email() string {
	return u.email
}

// EmailVerified returns trye if the associated users email field was verified.
func (u *IdentifiedUser) EmailVerified() bool {
	return u.emailVerified
}

// Name returns the associated users name field. This is the display name of
// the accociated user.
func (u *IdentifiedUser) Name() string {
	return u.displayName
}

// ID returns the associated users numeric user id. If it is 0, it means that
// this user does not have a numeric ID. Do not use this field to identiy a
// user - always use the subject instead. The numeric ID is kept for compatibilty
// with systems which require user identification to be numeric.
func (u *IdentifiedUser) ID() int64 {
	return u.id
}

// Username returns the accociated users username. This might be different or
// the same as the subject, depending on the backend in use. If can also be
// empty, which means that the accociated user does not have a username.
func (u *IdentifiedUser) Username() string {
	return u.username
}
