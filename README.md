# Konnect

## TL;DW

Make sure you have Go 1.8 installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
installed as well.

Furthermore this also assumes that you have a set-up Konano with a reverse proxy
on `https://mykopano.local` together with the proper proxy configuration to
pass through all requests to the `/konnect/v1/` prefix to `127.0.0.1:8777`. also
do not forget to reverse proxy `/.well-known/openid-configuration` as well.

```
mkdir -p ~/go/src/stash.kopano.io/kc
cd ~/go/src/stash.kopano.io/kc
git clone <THIS-PROJECT> konnect
cd konnect
glide install
go install -v ./cmd/konnectd && konnectd serve --listen 127.0.0.1:8777 \
  --iss=https://mykopano.local \
  --insecure \
  --signInFormURI=https://mykopano.local/webapp/index.php \
  cookie https://mykopano.local/webapp/plugins/kw-konnect/php/KwUserInfo.php KOPANO_WEBAPP
```

## Run unit tests

```
cd ~/go/src/stash.kopano.io/kc/konnect
go test -v $(glide novendor)
```

## Other implementations

There are some other noteworthy implementation of OpenID Connect out there which
can be used as reference for compatibility.

- https://github.com/coreos/dex
- https://github.com/ory/hydra
