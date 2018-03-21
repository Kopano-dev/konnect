# Konnect

Kopano Konnect implements an [OpenID provider](http://openid.net/specs/openid-connect-core-1_0.html)
(OP) with integrated web login and consent forms.

## Quickstart

Either download a Konnect binary release from https://download.kopano.io/community/konnect:/
or use the Docker image from https://hub.docker.com/r/kopano/konnectd/ to run
Konnect. For details how to run Konnect see below.

## Build dependencies

Make sure you have Go 1.8 or later installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
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

Konnect can provide user login with Kopano Groupware Core as backend, use a
cookie aware web login area which supports the ?continue parameter, or also can
directly connect to a LDAP server.

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

### Kopano Webapp backend (Cookie backend)

This assumes that you have a set-up Kopano with a reverse proxy on
`https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`. also
do not forget to reverse proxy `/.well-known/openid-configuration`.

Kopano Webapp needs to support the `?continue=` request parameter and the domains
of possible OIDC clients need to be added into `webapp/config.php` with the
`REDIRECT_ALLOWED_DOMAINS` setting.

```
bin/konnectd serve --listen=127.0.0.1:8777 \
  --iss=https://mykopano.local \
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

#### Run Konnect from Docker image

```
openssl rand 32 -out /etc/kopano/konnectd-encryption-secret.key
docker run --rm=true --name=konnectd \
	--read-only \
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
you adapt the parameters and environment variables.

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
