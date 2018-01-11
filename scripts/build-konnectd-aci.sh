#!/bin/sh

BINARY=bin/konnectd
IDENTIFIER_WEBAPP_BUILD=identifier/build
HOSTOS=$(go env GOHOSTOS)
ARCH=$(go env GOHOSTARCH)

make
VERSION=$($BINARY version|grep Version|awk -F': ' '{ print $2 }')
(cd identifier && make)

acbuild --debug begin
trap "{ export EXT=$?; acbuild --debug end && rm -rf $TMPDIR && exit $EXT; }" EXIT

acbuild --debug set-name kopano.com/konnectd
acbuild --debug set-user 301
acbuild --debug set-group 301
acbuild --debug copy $BINARY /srv/konnectd
acbuild --debug copy $IDENTIFIER_WEBAPP_BUILD /srv/identifier-webapp
acbuild --debug set-exec -- /srv/konnectd serve \
	--listen=0.0.0.0:8777 \
	--signing-private-key=/signing-private-key.pem \
	--encryption-secret=/encryption.key \
	--identifier-client-path=/srv/identifier-webapp
acbuild --debug port add www tcp 8777
acbuild --debug mount add signing-private-key /signing-private-key.pem --read-only
acbuild --debug mount add encryption-secret /encryption.key --read-only
acbuild --debug mount add etc-ssl-certs /etc/ssl/certs --read-only
acbuild --debug mount add run /run
acbuild --debug label add version $VERSION
acbuild --debug label add arch $ARCH
acbuild --debug label add os $HOSTOS
acbuild --debug write --overwrite kopano-konnectd-$VERSION-$HOSTOS-$ARCH.aci
