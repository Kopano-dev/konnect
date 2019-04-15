/*
 * Copyright 2019 Kopano and its licensors
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
	"crypto/tls"
	"net/http"
	"time"

	"stash.kopano.io/kc/konnect/version"
)

const defaultHTTPTimeout = time.Second * 30

// DefaultHTTPUserAgent is the User-Agent Header which should be used when
// making HTTP requests.
var DefaultHTTPUserAgent = "Kopano-Konnect/" + version.Version

// DefaultHTTPClient is a http.Client with a timeout set.
var DefaultHTTPClient = &http.Client{
	Timeout: defaultHTTPTimeout,
}

// InsecureHTTPClient is a http.Client with a timeout set and with TLS
// varification disabled.
var InsecureHTTPClient = &http.Client{
	Timeout: defaultHTTPTimeout,
	Transport: &http.Transport{
		// NOTE(longsleep): This disable http2 client support. See https://github.com/golang/go/issues/14275 for reasons.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}
