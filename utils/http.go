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

	"golang.org/x/net/http2"

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
	transport := &http.Transport{
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
	}
	if tlsClientConfig != nil {
		transport.TLSClientConfig = tlsClientConfig
		err := http2.ConfigureTransport(transport)
		if err != nil {
			panic(err)
		}
	}

	return transport
}

// DefaultTLSConfig returns a new tls.Config.
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
	}
}

// InsecureSkipVerifyTLSConfig returns a new tls.Config which does skip TLS verification.
func InsecureSkipVerifyTLSConfig() *tls.Config {
	config := DefaultTLSConfig()
	config.InsecureSkipVerify = true

	return config
}

// DefaultHTTPClient is a http.Client with a timeout set.
var DefaultHTTPClient = &http.Client{
	Timeout:   defaultHTTPTimeout,
	Transport: HTTPTransportWithTLSClientConfig(DefaultTLSConfig()),
}

// InsecureHTTPClient is a http.Client with a timeout set and with TLS
// varification disabled.
var InsecureHTTPClient = &http.Client{
	Timeout:   defaultHTTPTimeout,
	Transport: HTTPTransportWithTLSClientConfig(InsecureSkipVerifyTLSConfig()),
}
