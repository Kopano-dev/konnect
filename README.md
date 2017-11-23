# Konnect

## TL;DW

Make sure you have Go 1.8 installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
installed as well.

## Building from source

```
mkdir -p ~/go/src/stash.kopano.io/kc
cd ~/go/src/stash.kopano.io/kc
git clone <THIS-PROJECT> konnect
cd konnect
make
```

## Running Konnect

Konnect can provide a full user login with Kopano Groupware Core as backend or
use any cookie aware login area which supports the ?continue parameter and
is based on cookies.

All backends require certain general parameters to be present. Create a  RSA
key-pair and provide the provide key file with the `--key` parameter. If you
skip this, Konnect will create a key pair on startup.

To encrypt certain values, Konnect needs a secure key. Create a hex-key with
`openssl rand -hex 32` and provide it with via the `--secret` parameter.

### Kopano Webapp backend (Cookie backend)

This assumes that you have a set-up Konano with a reverse proxy on
`https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`. also
do not forget to reverse proxy `/.well-known/openid-configuration` as well.

Kopano Webapp needs to support the `?continue=` request parameter and the domains
of possible OIDC clients need to be added into `webapp/config.php` with the
`REDIRECT_ALLOWED_DOMAINS` setting.

```
bin/konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykopano.local \
  --insecure \
  --secret=$(openssl rand -hex 32) \
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
  --insecure \
  --secret=$(openssl rand -hex 32) \
  kc
```

## Run unit tests

```
cd ~/go/src/stash.kopano.io/kc/konnect
make test
```
