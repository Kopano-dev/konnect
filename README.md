# Konnect

Kopano Konnect implements an [OpenID provider](openid.net/specs/openid-connect-core-1_0.html) (OP) with integrated web login and consent forms.

## Quick start

Make sure you have Go 1.8 or later installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
installed as well.

Konnect also includes a modern web app which requires [Yarn](https://yarnpkg.com). Thus it
is furthermore assumed that you have `yarn` in your $PATH.

## Building from source

```
mkdir -p ~/go/src/stash.kopano.io/kc
cd ~/go/src/stash.kopano.io/kc
git clone <THIS-PROJECT> konnect
cd konnect
make
```

### Optional build dependencies

Some optional build dependencies are required for linting and continous
integration. Those tools are mostly used by make to perform various tasks and
are expected to be found in your $PATH.

  - https://github.com/golang/lint
  - https://github.com/tebeka/go2xunit

## Running Konnect

Konnect can provide user login with Kopano Groupware Core as backend, use a
cookie aware web login area which supports the ?continue parameter, or also can
directly connect to a LDAP server.

All backends require certain general parameters to be present. Create a RSA
key-pair and provide the key file with the `--signing-private-key` parameter.
If you skip this, Konnect will create a random non-persistent key on startup.

To encrypt certain values, Konnect needs a secure encryption key. Create a
suitable key of 32 bytes with `openssl rand -out encryption.key 32` and provide
the full path to that file via the `--encryption-secret` parameter. If you skip
this, Konnect will generate a random key on startup.

## URL endpoints

Take a look at `Caddyfile.example` on the URL endpoints provided by Konnect and
how to expose them through a TLS proxy.

The base URL of the frontend proxy is what will become the value of the `--iss`
parameter when starting up Konnect. OIDC requires the Issuer Identifier to be
secure (https:// required).

### Kopano Webapp backend (Cookie backend)

This assumes that you have a set-up Konano with a reverse proxy on
`https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`. also
do not forget to reverse proxy `/.well-known/openid-configuration`.

Kopano Webapp needs to support the `?continue=` request parameter and the domains
of possible OIDC clients need to be added into `webapp/config.php` with the
`REDIRECT_ALLOWED_DOMAINS` setting.

```
bin/konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykopano.local \
  --insecure \
  --sign-in-uri=https://mykopano.local/webapp/ \
  cookie https://mykopano.local/webapp/?load=custom&name=oidcuser "KOPANO_WEBAPP encryption-store-key"
```

### Kopano Groupware Core backend

This assumes that Konnect can connect directly to a Kopano server via SOAP
either using a unix socket or a TCP connection.

```
export KOPANO_SERVER_DEFAULT_URI=http://mykopano.local:236
export KOPANO_SERVER_USERNAME=my-kopano-user
export KOPANO_SERVER_PASSWORD=my-kopano-password

bin/konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykonnect.local \
  --insecure
  kc
```

### LDAP backend

This assumes that Konnect can directly connect to an LDAP server via TCP.

```
export LDAP_URI=ldap://myldap.local:389
export LDAP_BINDDN="cn=admin,dc=example,dc=local"
export LDAP_BINDPW="its-a-secret"
export LDAP_BASEDN="dc=example,dc=local"
export LDAP_SCOPE=sub
export LDAP_LOGIN_ATTRIBUTE=uid
export LDAP_EMAIL_ATTRIBUTE=mail
export LDAP_NAME_ATTRIBUTE=cn
export LDAP_FILTER="(objectClass=organizationalPerson)"

bin/konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykonnect.local \
  --insecure \
  ldap
```

## Run unit tests

```
cd ~/go/src/stash.kopano.io/kc/konnect
make test
```

### Development

As Konnect includes a web application (identifier), a `Caddyfile.dev` file is
provided which exposes the identifier's web application directly via a
webpack dev server.
