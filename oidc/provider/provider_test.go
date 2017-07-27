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

package provider

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"

	identityManagers "stash.kopano.io/kc/konnect/identity/managers"
	codeManagers "stash.kopano.io/kc/konnect/oidc/code/managers"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{DisableColors: true},
	Level:     logrus.DebugLevel,
}

var rsaPrivateKeyBytes = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAMJQfNl1V9opRN58oFZ0qxnIZexDZCNJOJqlzew6rDu46Tegd2e7
uPPhQ0wQ7JQ/pvpMWBR9ayDNirdPQKAHFAECAwEAAQJBAKXVQSfpQEe8rrzeSYxf
V2LSp0GCpiSDKd65oEt6K2FvSj+jIh7K/bsEs/0B1FBX0ISP1eXY5ojhohLkR1HN
NV0CIQDjPnPsbv6+0wfo014w88uIbQY+INzhZm+vbG3ZFuRZwwIhANrnSPoKAvQW
J69xBfTOquvU5hTfYQsMqob8LkZ7+7rrAiEApnlbHUtXDl60/ajS6RPA+Gm+WAdl
KS8NBLtvYck2clcCIFToGPpDH9olLcdzA2htMQbAUW4PJsjuZMZu0lQsivt5AiBe
iL15eI5KhPbmAaTZBrhZ1l9MkpCrwGTjD4zOPUqD9A==
-----END RSA PRIVATE KEY-----`)

var rsaPrivateKey crypto.Signer

func init() {
	block, _ := pem.Decode(rsaPrivateKeyBytes)
	rsaPrivateKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
}

func NewTestProvider(ctx context.Context, t *testing.T) (*httptest.Server, *Provider, http.Handler, *Config) {
	config := &Config{
		IssuerIdentifier:  "http://localhost:8777",
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: "/konnect/v1/authorize",
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",

		IdentityManager: &identityManagers.DummyIdentityManager{
			Sub: "unittestuser",
		},
		CodeManager: codeManagers.NewMemoryMapManager(ctx),
		Logger:      logger,
	}

	provider, err := NewProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	provider.SetSigningKey("default", rsaPrivateKey, jwt.SigningMethodRS256)

	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		provider.ServeHTTP(rw, req)
	}))

	return s, provider, provider, config
}

func TestNewTestProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	NewTestProvider(ctx, t)
}
