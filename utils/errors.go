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

package utils

import (
	"fmt"
)

// ErrorWithDescription is an interface binding the standard error
// inteface with a description.
type ErrorWithDescription interface {
	error
	Description() string
}

// DescribeError returns a wrapped version for errors which contain additional
// fields. The wrapped version contains all fields as a string value. Use this
// for general purpose logging of rich errors.
func DescribeError(err error) error {
	switch err.(type) {
	case ErrorWithDescription:
		err = fmt.Errorf("%s - %s", err, err.(ErrorWithDescription).Description())
	}

	return err
}

// ErrorAsFields returns a mapping of all fields of the provided error.
func ErrorAsFields(err error) map[string]interface{} {
	if err == nil {
		return nil
	}

	fields := make(map[string]interface{})
	fields["error"] = err.Error()
	switch err.(type) {
	case ErrorWithDescription:
		fields["desc"] = err.(ErrorWithDescription).Description()
	}

	return fields
}
