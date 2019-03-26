# Konnect

Kopano Konnect implements an [OpenID provider](http://openid.net/specs/openid-connect-core-1_0.html)
(OP) with integrated web login and consent forms.

[![Go Report Card](https://goreportcard.com/badge/stash.kopano.io/kc/konnect)](https://goreportcard.com/report/stash.kopano.io/kc/konnect)

## Quickstart

Either download a Konnect binary release from https://download.kopano.io/community/konnect:/
or use the Docker image from https://hub.docker.com/r/kopano/konnectd/ to run
Konnect. For details how to run Konnect see below.

## Standards supported by Konnect

Konnect provides services based on open standards. To get you an idea what
Konnect can do and how you could use it, this section lists the
[OpenID Connect](https://openid.net/connect/) standards which are implemented.

- https://openid.net/specs/openid-connect-core-1_0.html
- https://openid.net/specs/openid-connect-discovery-1_0.html
- https://openid.net/specs/openid-connect-frontchannel-1_0.html
- https://openid.net/specs/openid-connect-session-1_0.html
- https://openid.net/specs/openid-connect-registration-1_0.html

Furthermore the following extensions/base specifications extend, define and
combine the implementation details.

- https://tools.ietf.org/html/rfc6749
- https://tools.ietf.org/html/rfc7517
- https://tools.ietf.org/html/rfc7519
- https://tools.ietf.org/html/rfc7636
- https://tools.ietf.org/html/rfc7693
- https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
- https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
- https://www.iana.org/assignments/jose/jose.xhtml
- https://nacl.cr.yp.to/secretbox.html

## Build dependencies

Make sure you have Go 1.10 or later installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Dep](https://golang.github.io/dep/)
installed as well.

Konnect also includes a modern web app which requires a couple of additional
build dependencies which are furthermore also assumed to be in your $PATH.

  - yarn - [Yarn](https://yarnpkg.com)
  - convert, identify - [Imagemagick](https://www.imagemagick.org)
  - scour - [Scour](https://github.com/scour-project/scour)

To build Konnect, a `Makefile` is provided, which requires [make](https://www.gnu.org/software/make/manual/make.html).

When building, third party dependencies will tried to be fetched from the Internet
if not there already.

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

  - golint - [Golint](https://github.com/golang/lint)
  - go2xunit - [go2xunit](https://github.com/tebeka/go2xunit)

## Running Konnect

Konnect can provide user login with Kopano Groupware Storage server as backend,
use a cookie aware web login area which supports the ?continue parameter, or
also can directly connect to a LDAP server.

All backends require certain general parameters to be present. Create a RSA
key-pair file with `openssl genpkey -algorithm RSA -out private-key.pem -pkeyopt rsa_keygen_bits:4096`
and provide the key file with the `--signing-private-key` parameter. Konnect can
load PKCS#1 and PKCS#8 key files. If you skip this, Konnect will create a random
non-persistent RSA key on startup.

To encrypt certain values, Konnect needs a secure encryption key. Create a
suitable key of 32 bytes with `openssl rand -out encryption.key 32` and provide
the full path to that file via the `--encryption-secret` parameter. If you skip
this, Konnect will generate a random key on startup.

To run a functional OpenID Connect provider, an issuer identifier is required.
The `iss` is a full qualified https:// URI pointing to the web server which
serves the requests to Konnect (example: https://example.com). Provide the
Issuer Identifier with the `--iss` parametter when starting Konnect.

Furthermore to allow clients to utilize the Konnect services, clients need to
be known/registered. For now Konnect uses a static configuration file which
allows clients and their allowed urls to be registered. See the the example at
`identifier-registration.yaml.in`. Copy and modify that file to include all
the clients which should be able to use OpenID Connect and/or OAuth2 and start
Konnect with the `--identifier-registration-conf` parameter pointing to that
file. Without any explicitly registered clients, Konnect will only accept clients
which redirect to an URI which starts with the value provided with the `--iss`
parameter.

## URL endpoints

Take a look at `Caddyfile.example` on the URL endpoints provided by Konnect and
how to expose them through a TLS proxy.

The base URL of the frontend proxy is what will become the value of the `--iss`
parameter when starting up Konnect. OIDC requires the Issuer Identifier to be
secure (https:// required).

### Kopano Groupware Storage server backend

This assumes that Konnect can connect directly to a Kopano server via SOAP
either using a unix socket or a TCP connection.

Kopano Groupware Storage server backend connections can either use a dedicated
service connection which might require a certain unix user to access the
unix socket (not recommended) or bind the Konnect session and tokens to the
underlaying Groupware Storage server's session (default).

```
export KOPANO_SERVER_DEFAULT_URI=http://mykopano.local:236

bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykonnect.local \
  kc
```
Give dedicated session credentials via environment variables as shown in the
example below.

```
export KOPANO_SERVER_DEFAULT_URI=http://mykopano.local:236
export KOPANO_SERVER_USERNAME=my-kopano-user
export KOPANO_SERVER_PASSWORD=my-kopano-password

bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykonnect.local \
  kc
```

Or run konnect as local_admin_unix user. Only run konnectd like this when you
actually use that authentication scheme. Otherwise ensure that Konnect is not
running as local admin user for best security.

```
su - kopano
export KOPANO_SERVER_DEFAULT_URI=file:///run/kopano/server.sock
export KOPANO_SERVER_USERNAME=SYSTEM

bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykonnect.local \
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
export LDAP_UUID_ATTRIBUTE=uidNumber
export LDAP_UUID_ATTRIBUTE_TYPE=text
export LDAP_FILTER="(objectClass=organizationalPerson)"

bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykonnect.local \
  ldap
```

### Cookie backend

A cookie backend is also there for testing. It has limited amount of features
and should not be used in production. Essentially this backend assumes a login
area uses a HTTP cookie for authentication and Konnect is runnig in the same
scope as this cookie so the Konnect request can read and validate the cookie
using an internal proxy request.

This assumes that you have a set-up Kopano with a reverse proxy on
`https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`.
Kopano Webapp supports the `?continue=` request parameter and the domains
of possible OIDC clients need to be added into `webapp/config.php` with the
`REDIRECT_ALLOWED_DOMAINS` setting.

```
bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykopano.local \
  --sign-in-uri=https://mykopano.local/webapp/ \
  cookie https://mykopano.local/webapp/?load=custom&name=oidcuser "KOPANO_WEBAPP encryption-store-key"
```

### Run with Docker

Kopano Konnect supports Docker to easily be run inside a container. Running with
Docker supports all features of Kopano Konnect and can make use of Docker
Secrets to manage sensitive data like keys.

Kopano provides [official Docker images for Konnect](https://hub.docker.com/r/kopano/konnectd/).

```
docker pull kopano/konnectd
```

#### Run Konnect with Docker Swarm

Setup the Docker container in swarm mode like this:

```
cat /etc/kopano/konnectd-tokens-signing-key.pem | docker secret create konnectd_signing_private_key -
openssl rand 32 | docker secret create konnectd_encryption_secret -
docker service create \
	--read-only \
	--user=$(id -u kopano) \
	--group=$(id -g kopano) \
	--mount type=bind,source=/etc/ssl/certs,target=/etc/ssl/certs,readonly \
	--secret konnectd_signing_private_key \
	--secret konnectd_encryption_secret \
	--env KOPANO_SERVER_DEFAULT_URI=file:///run/kopano/server.sock \
	--mount type=bind,source=/run/kopano,target=/run/kopano \
	--publish published=8777,target=8777,mode=host \
	--name=konnectd \
	kopano/konnectd \
	serve \
	--iss=https://mykonnect.local \
	kc
```

This example assumes the local system has a user `kopano` which can access
the Kopano Groupware Core unix socket as admin user `SYSTEM`.

#### Run Konnect from Docker image

```
openssl rand 32 -out /etc/kopano/konnectd-encryption-secret.key
docker run --rm=true --name=konnectd \
	--read-only \
	--user=$(id -u kopano):$(id -g kopano) \
	--volume /etc/ssl/certs:/etc/ssl/certs:ro \
	--volume /etc/kopano/konnectd-tokens-signing-key.pem:/run/secrets/konnectd_signing_private_key:ro \
	--volume /etc/kopano/konnectd-encryption.key:/run/secrets/konnectd_encryption_secret:ro \
	--env KOPANO_SERVER_DEFAULT_URI=file:///run/kopano/server.sock \
	--volume /run/kopano:/run/kopano:rw \
	--publish 127.0.0.1:8777:8777 \
	kopano/konnectd \
	serve \
	--iss=https://mykonnect.local \
	kc
```

Of course modify the paths and ports according to your requirements. The Docker
examples are for the kc identity manager, but work for the others as well if
you adapt the parameters and environment variables. The above example assumes
the local system has a user `kopano` which can access the Kopano Groupware Core
unix socket as admin user `SYSTEM`.

#### Build Konnect Docker image

This project includes a `Dockerfile` which can be used to build a Docker
container from the locally build version. Similarly the `Dockerfile.release`
builds the Docker image locally from the latest release download.

```
docker build -t kopano/konnectd .
```

```
docker build -f Dockerfile.release -t kopano/konnectd .
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
