/*
 * Copyright 2018 Kopano and its licensors
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

package payload

// Session defines a Provider's session with a String identifier for a Session.
// This represents a Session of a User Agent or device for a logged-in End-User
// at an RP. Different ID values are used to identify distinct sessions. This
// is implemented as defined in the OIDC Front Channel logout extension
// https://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
type Session struct {
	Version  int
	ID       string
	Sub      string
	Provider string
}
