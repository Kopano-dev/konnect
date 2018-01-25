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

package ldap

// Define some known LDAP attribute descriptors.
const (
	AttributeDN         = "dn"
	AttributeLogin      = "uid"
	AttributeEmail      = "mail"
	AttributeName       = "cn"
	AttributeFamilyName = "sn"
	AttributeGivenName  = "givenName"
	AttributeUUID       = "uuid"
)

// Define our known LDAP attribute value types.
const (
	AttributeValueTypeText   = "text"
	AttributeValueTypeBinary = "binary"
	AttributeValueTypeUUID   = "uuid"
)
