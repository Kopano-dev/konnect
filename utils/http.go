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
	"net"
	"net/http"
	"time"

	"stash.kopano.io/kc/konnect/version"
)

const (
	defaultHTTPTimeout               = 30 * time.Second
	defaultHTTPKeepAlive             = 30 * time.Second
	defaultHTTPMaxIdleConns          = 100
	defaultHTTPIdleConnTimeout       = 90 * time.Second
	defaultHTTPTLSHandshakeTimeout   = 10 * time.Second
	defaultHTTPExpectContinueTimeout = 1 * time.Second
)

// DefaultHTTPUserAgent is the User-Agent Header which should be used when
// making HTTP requests.
var DefaultHTTPUserAgent = "Kopano-Konnect/" + version.Version

// HTTPTransportWithTLSClientConfig creates a new http.Transport with sane
// default settings using the provided tls.Config.
func HTTPTransportWithTLSClientConfig(tlsClientConfig *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   defaultHTTPTimeout,
			KeepAlive: defaultHTTPKeepAlive,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          defaultHTTPMaxIdleConns,
		IdleConnTimeout:       defaultHTTPIdleConnTimeout,
		TLSHandshakeTimeout:   defaultHTTPTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultHTTPExpectContinueTimeout,

		TLSClientConfig: tlsClientConfig,
	}
}

// DefaultHTTPClient is a http.Client with a timeout set.
var DefaultHTTPClient = &http.Client{
	Timeout:   defaultHTTPTimeout,
	Transport: HTTPTransportWithTLSClientConfig(nil),
}

// InsecureSkipVerifyTLSConfig is a tls.Config which does skip TLS verification.
var InsecureSkipVerifyTLSConfig = &tls.Config{InsecureSkipVerify: true}

// InsecureHTTPClient is a http.Client with a timeout set and with TLS
// varification disabled.
var InsecureHTTPClient = &http.Client{
	Timeout:   defaultHTTPTimeout,
	Transport: HTTPTransportWithTLSClientConfig(InsecureSkipVerifyTLSConfig),
}
