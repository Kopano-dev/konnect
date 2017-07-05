# Konnect

## TL;DR

Make sure you have Go 1.8 installed. This assumes your GOPATH is `~/go` and
you have `~/go/bin` in your $PATH and you have [Glide](https://github.com/Masterminds/glide)
installed as well.

```
mkdir -p ~/go/src/stash.kopano.io/kc
cd ~/go/src/stash.kopano.io/kc
git clone <THIS-PROJECT> konnect
cd konnect
glide install
go install -v ./cmd/konnectd/... && konnectd serve --listen 0.0.0.0:8777
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
