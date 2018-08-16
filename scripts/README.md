# Scripts and helpers for Kopano Konnect

This folder contains various scripts and helpers to integrate Konnect with
various ways how it can be started and configured.

## Rkt

Rkt is a pod-native container engine for Linux. Here are some examples how to
integrate/run konnect with rkt. The following section is kept here as example.

### Config file as systemd environment file

```
# OpenID Connect Issuer Identifier
ISS=https://konnect.local

# Full file path to a PEM encoded PKCS#1 or PKCS#5 private key which is used to
# sign tokens. This file must exist and be valid to be able to start the
# service. A suitable key can be generated with:
#   `openssl genpkey -algorithm RSA \
#     -out konnectd-signing-private-key.pem.pem \
#     -pkeyopt rsa_keygen_bits:4096`
SIGNING_PRIVATE_KEY=/etc/kopano/konnectd-signing-private-key.pem

# Full file path to a encryption secret key file containing random bytes. This
# file must exist to be able to start the service. A suitable file can be
# generated with:
#   `openssl rand -out konnectd-encryption.key 32`
ENCRYPTION_SECRET=/etc/kopano/konnectd-encryption.key

# Full file path to the identifier registration configuration file. This file
# must exist to be able to start the service. An example file is shipped with
# the documentation / sources.
IDENTIFIER_REGISTRATION_CONF=/etc/kopano/konnectd-identifier-registration.yaml

# Identity manager Kopano Core via direct connection.
IDENTITY_MANAGER=kc
KOPANO_SERVER_DEFAULT_URI=file:///run/kopano-server.sock
KOPANO_SERVER_USERNAME=SYSTEM
KOPANO_SERVER_PASSWORD=

# Identity manager Kopano Webapp via Cookie pass through.
#SIGN_IN_URL=https://your-kopano.local/webapp/index.php
#IDENTITY_MANAGER=cookie "$SIGN_IN_URL?load=custom&name=oidcuser" KOPANO_WEBAPP encryption-store-key

#IMAGE=/srv/images/kopano-konnectd-latest-linux-amd64.aci
#RKT_ARGS=--port=www:127.0.0.1:8777
#ARGS=--insecure
```

### Systemd service with rkt

```
[Unit]
Description=kopano-konnectd
Requires=network-online.target
After=network-online.target

[Service]
Slice=machine.slice
Environment=RKT_ARGS=--port=www:127.0.0.1:8777
Environment=ISS=https://konnect.local
Environment=SIGNING_PRIVATE_KEY=/etc/kopano/konnectd-tokens-signing-key.pem
Environment=ENCRYPTION_SECRET=/etc/kopano/konnectd-encryption.key
Environment=IDENTIFIER_REGISTRATION_CONF=/etc/kopano/konnectd-identifier-registration.yaml
Environment=IMAGE=/srv/images/kopano-konnectd-latest-linux-amd64.aci
EnvironmentFile=/etc/default/kopano-konnectd
ExecStart=/usr/bin/rkt \
	--insecure-options=image \
	run $RKT_ARGS \
	--volume signing-private-key,kind=host,source=${SIGNING_PRIVATE_KEY} \
	--volume encryption-secret,kind=host,source=${ENCRYPTION_SECRET} \
	--volume identifier-registration-conf,kind=host,source=${IDENTIFIER_REGISTRATION_CONF} \
	--volume etc-ssl-certs,kind=host,source=/etc/ssl/certs \
	--volume run,kind=host,source=/run \
	${IMAGE} \
	--environment=KOPANO_SERVER_DEFAULT_URI="$KOPANO_SERVER_DEFAULT_URI" \
	--environment=KOPANO_SERVER_USERNAME="$KOPANO_SERVER_USERNAME" \
	--environment=KOPANO_SERVER_PASSWORD="$KOPANO_SERVER_PASSWORD" \
	-- \
	--iss=${ISS} \
	--sign-in-uri=${SIGN_IN_URL} \
	$ARGS $IDENTITY_MANAGER
ExecStopPost=/usr/bin/rkt gc --mark-only
KillMode=mixed
Restart=always
```
