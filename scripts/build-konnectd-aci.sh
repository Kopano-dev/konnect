#!/bin/sh

BINARY=bin/konnectd
HOSTOS=$(go env GOHOSTOS)
ARCH=$(go env GOHOSTARCH)

make
VERSION=$($BINARY version|grep Version|awk -F': ' '{ print $2 }')

acbuild --debug begin
trap "{ export EXT=$?; acbuild --debug end && rm -rf $TMPDIR && exit $EXT; }" EXIT

acbuild --debug set-name kopano.com/konnectd
acbuild --debug set-user 301
acbuild --debug set-group 301
acbuild --debug copy $BINARY /bin/konnectd
acbuild --debug set-exec -- /bin/konnectd serve \
	--listen=0.0.0.0:8777 \
	--key=/key.pem
acbuild --debug port add www tcp 8777
acbuild --debug mount add key /key.pem --read-only
acbuild --debug mount add etc-ssl-certs /etc/ssl/certs --read-only
acbuild --debug label add version $VERSION
acbuild --debug label add arch $ARCH
acbuild --debug label add os $HOSTOS
acbuild --debug write --overwrite kopano-konnectd-$VERSION-$HOSTOS-$ARCH.aci
