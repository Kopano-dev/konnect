# Konnect

## TL;DW

Make sure you have Go 1.8 installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
installed as well.

Furthermore this also assumes that you have a set-up Konano with a reverse proxy
on `https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`. also
do not forget to reverse proxy `/.well-known/openid-configuration` as well.

Kopano Webapp needs to support the `?continue=` request parameter and the domains
of possible OIDC clients need to be added into `webapp/config.php` with the
`REDIRECT_ALLOWED_DOMAINS` setting.

```
mkdir -p ~/go/src/stash.kopano.io/kc
cd ~/go/src/stash.kopano.io/kc
git clone <THIS-PROJECT> konnect
cd konnect
make
bin/konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykopano.local \
  --insecure \
  --signInFormURI=https://mykopano.local/webapp/ \
  cookie https://mykopano.local/webapp/?load=custom&name=oidcuser KOPANO_WEBAPP encryption-store-key
```

For continuous use, create a RSA key-pair and provide the provide key file with
the `--key` parameter.

Konnect can encrypt certain values inside its tokens. For that,
create a hex-key with `openssl rand -hex 32` and provide it with via the
`--secret` parameter.

## Run unit tests

```
cd ~/go/src/stash.kopano.io/kc/konnect
make test
```
