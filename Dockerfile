#!/bin/sh
#
# Copyright 2018 Kopano and its licensors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License, version 3 or
# later, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

FROM alpine:3.7
MAINTAINER Kopano Development <development@kopano.io>

# Expose ports.
EXPOSE 8777

# Define basic environment variables.
ENV EXE=konnectd
ENV KONNECTD_LISTEN=0.0.0.0:8777
ENV KONNECTD_IDENTIFIER_CLIENT_PATH=/var/lib/konnectd-docker/identifier-webapp
ENV KONNECTD_SIGNING_PRIVATE_KEY_FILE=konnectd_signing_private_key
ENV KONNECTD_ENCRYPTION_SECRET_FILE=konnectd_encryption_secret
ENV KONNECTD_KOPANO_SERVER_USERNAME_FILE=konnectd_kopano_server_username
ENV KONNECTD_KOPANO_SERVER_PASSWORD_FILE=konnectd_kopano_server_password
ENV KONNECTD_LDAP_BIND_DN_FILE=konnectd_ldap_bind_dn
ENV KONNECTD_LDAP_BIND_PASSWORD_FILE=konnectd_ldap_bind_password

# Defaults which can be overwritten.
ENV KOPANO_SERVER_DEFAULT_URI=file://run/kopano/server.sock
ENV KOPANO_SERVER_USERNAME=
ENV KOPANO_SERVER_PASSWORD=
ENV LDAP_URI=
ENV LDAP_BINDDN=
ENV LDAP_BINDPW=

WORKDIR /var/lib/konnectd-docker

# Copy Docker specific scripts and ensure they are executable.
COPY \
	scripts/docker-entrypoint.sh \
	scripts/healthcheck.sh \
	/usr/local/bin/
RUN chmod 755 /usr/local/bin/*.sh

# Add Docker specific runtime setup functions.
RUN mkdir /etc/defaults && echo $'\
setup_secrets() { \n\
	local signingPrivateKeyFile="/run/secrets/${KONNECTD_SIGNING_PRIVATE_KEY_FILE}" \n\
	if [ -f "${signingPrivateKeyFile}" ]; then \n\
		export KONNECTD_SIGNING_PRIVATE_KEY="${signingPrivateKeyFile}" \n\
	fi \n\
	local encryptionSecretFile="/run/secrets/${KONNECTD_ENCRYPTION_SECRET_FILE}" \n\
	if [ -f "${encryptionSecretFile}" ]; then \n\
		export KONNECTD_ENCRYPTION_SECRET="${encryptionSecretFile}" \n\
	fi \n\
	local kopanoServerUsernameFile="/run/secrets/${KONNECTD_KOPANO_SERVER_USERNAME_FILE}" \n\
	if [ -f "${kopanoServerUsernameFile}" ]; then \n\
		export KOPANO_SERVER_USERNAME="$(cat ${kopanoServerUsernameFile})" \n\
	fi \n\
	local kopanoServerPasswordFile="/run/secrets/${KONNECTD_KOPANO_SERVER_PASSWORD_FILE}" \n\
	if [ -f "${kopanoServerPasswordFile}" ]; then \n\
		export KOPANO_SERVER_PASSWORD="$(cat ${kopanoServerPasswordFile})" \n\
	fi \n\
	local ldapBindDNFile="/run/secrets/${KONNECTD_LDAP_BIND_DN_FILE}" \n\
	if [ -f "${ldapBindDNFile}" ]; then \n\
		export LDAP_BINDDN="$(cat ${ldapBindDNFile})" \n\
	fi \n\
	local ldapBindPasswordFile="/run/secrets/${KONNECTD_LDAP_BIND_PASSWORD_FILE}" \n\
	if [ -f "${ldapBindPasswordFile}" ]; then \n\
		export LDAP_BINDPW="$(cat ${ldapBindPasswordFile})" \n\
	fi \n\
}\n\
setup_secrets\n\
' > /etc/defaults/docker-env

# Add project resources.
ADD identifier/build /var/lib/konnectd-docker/identifier-webapp

# Add project main binary.
COPY bin/konnectd /usr/local/bin/${EXE}

# Run as nobody by default is always a good idea.
USER nobody

ENTRYPOINT ["docker-entrypoint.sh"]
CMD [ \
	"konnectd", \
	"--help" \
	]

# Health check support is cool too.
HEALTHCHECK --interval=30s --timeout=5s \
	CMD healthcheck.sh