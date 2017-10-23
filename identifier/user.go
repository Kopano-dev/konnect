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

type IdentifiedUser struct {
	sub string

	username      string
	email         string
	emailVerified bool
	displayName   string

	id int64
}

func (u *IdentifiedUser) Subject() string {
	return u.sub
}

func (u *IdentifiedUser) Email() string {
	return u.email
}

func (u *IdentifiedUser) EmailVerified() bool {
	return u.emailVerified
}

func (u *IdentifiedUser) Name() string {
	return u.displayName
}

func (u *IdentifiedUser) ID() int64 {
	return u.id
}

func (u *IdentifiedUser) Username() string {
	return u.username
}
