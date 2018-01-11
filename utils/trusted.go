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
	"net"
	"net/http"
)

// IsRequestFromTrustedSource checks if the provided requests remote address is
// one either one of the provided ips or in one of the provided networks.
func IsRequestFromTrustedSource(req *http.Request, ips []*net.IP, nets []*net.IPNet) (bool, error) {
	ipString, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return false, err
	}

	ip := net.ParseIP(ipString)

	for _, checkIP := range ips {
		if checkIP.Equal(ip) {
			return true, nil
		}
	}

	for _, checkNet := range nets {
		if checkNet.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}
