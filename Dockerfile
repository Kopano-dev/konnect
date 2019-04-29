#!/bin/sh
#
# Copyright 2017-2019 Kopano and its licensors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FROM alpine:3.9
MAINTAINER Kopano Development <development@kopano.io>

RUN apk add --update \
	su-exec \
	&& rm -rf /var/cache/apk/*

# Expose ports.
EXPOSE 8777

# Define basic environment variables.
ENV EXE=konnectd
ENV KONNECTD_LISTEN=0.0.0.0:8777
ENV KONNECTD_IDENTIFIER_CLIENT_PATH=/var/lib/konnectd-docker/identifier-webapp
ENV KONNECTD_DOCKER_SECRETS_PATH=/run/secrets
ENV KONNECTD_SIGNING_PRIVATE_KEY_FILE=konnectd_signing_private_key
ENV KONNECTD_ENCRYPTION_SECRET_FILE=konnectd_encryption_secret
ENV KONNECTD_KOPANO_SERVER_USERNAME_FILE=konnectd_kopano_server_username
ENV KONNECTD_KOPANO_SERVER_PASSWORD_FILE=konnectd_kopano_server_password
ENV KONNECTD_LDAP_BIND_DN_FILE=konnectd_ldap_bind_dn
ENV KONNECTD_LDAP_BIND_PASSWORD_FILE=konnectd_ldap_bind_password

# Defaults which can be overwritten.
ENV KOPANO_SERVER_DEFAULT_URI=file:///run/kopano/server.sock
ENV KOPANO_SERVER_USERNAME=
ENV KOPANO_SERVER_PASSWORD=
ENV KOPANO_SERVER_SESSION_TIMEOUT=
ENV LDAP_URI=
ENV LDAP_BINDDN=
ENV LDAP_BINDPW=
ENV ARGS=

# User and group defaults.
ENV KONNECTD_USER=nobody
ENV KONNECTD_GROUP=nogroup

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
	local signingPrivateKeyFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_SIGNING_PRIVATE_KEY_FILE}" \n\
	if [ -f "${signingPrivateKeyFile}" ]; then \n\
		export KONNECTD_SIGNING_PRIVATE_KEY="${signingPrivateKeyFile}" \n\
	fi \n\
	local encryptionSecretFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_ENCRYPTION_SECRET_FILE}" \n\
	if [ -f "${encryptionSecretFile}" ]; then \n\
		export KONNECTD_ENCRYPTION_SECRET="${encryptionSecretFile}" \n\
	fi \n\
	local kopanoServerUsernameFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_KOPANO_SERVER_USERNAME_FILE}" \n\
	if [ -f "${kopanoServerUsernameFile}" ]; then \n\
		export KOPANO_SERVER_USERNAME="$(cat ${kopanoServerUsernameFile})" \n\
	fi \n\
	local kopanoServerPasswordFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_KOPANO_SERVER_PASSWORD_FILE}" \n\
	if [ -f "${kopanoServerPasswordFile}" ]; then \n\
		export KOPANO_SERVER_PASSWORD="$(cat ${kopanoServerPasswordFile})" \n\
	fi \n\
	local ldapBindDNFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_LDAP_BIND_DN_FILE}" \n\
	if [ -f "${ldapBindDNFile}" ]; then \n\
		export LDAP_BINDDN="$(cat ${ldapBindDNFile})" \n\
	fi \n\
	local ldapBindPasswordFile="${KONNECTD_DOCKER_SECRETS_PATH}/${KONNECTD_LDAP_BIND_PASSWORD_FILE}" \n\
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

ENTRYPOINT ["docker-entrypoint.sh"]
CMD [ \
	"konnectd", \
	"--help" \
	]

# Health check support is cool too.
HEALTHCHECK --interval=30s --timeout=5s \
	CMD healthcheck.sh
