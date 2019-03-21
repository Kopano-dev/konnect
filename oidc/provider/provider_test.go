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

	"stash.kopano.io/kc/konnect/config"
	"stash.kopano.io/kc/konnect/managers"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/identity/clients"
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
	mgrs := managers.New()
	mgrs.Set("identity", identityManagers.NewDummyIdentityManager(
		&identity.Config{},
		"unittestuser",
	))
	mgrs.Set("code", codeManagers.NewMemoryMapManager(ctx))
	encryptionManager, _ := identityManagers.NewEncryptionManager(nil)
	mgrs.Set("encryption", encryptionManager)
	mgrs.Set("clients", &clients.Registry{})

	cfg := &Config{
		Config: &config.Config{
			Logger: logger,
		},

		IssuerIdentifier:  "http://localhost:8777",
		WellKnownPath:     "/.well-known/openid-configuration",
		JwksPath:          "/konnect/v1/jwks.json",
		AuthorizationPath: "/konnect/v1/authorize",
		TokenPath:         "/konnect/v1/token",
		UserInfoPath:      "/konnect/v1/userinfo",
	}

	p, err := NewProvider(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.SetSigningKey("default", rsaPrivateKey, jwt.SigningMethodPS256)
	err = p.RegisterManagers(mgrs)
	if err != nil {
		t.Fatal(err)
	}
	err = p.InitializeMetadata()
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		p.ServeHTTP(rw, req)
	}))

	return s, p, p, cfg
}

func TestNewTestProvider(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	NewTestProvider(ctx, t)
}
