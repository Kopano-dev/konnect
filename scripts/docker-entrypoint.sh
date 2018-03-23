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

set -euo pipefail

# Check for parameters, prepend with our exe when the first arg is a parameter.
if [ "${1:0:1}" = '-' ]; then
	set -- ${EXE} "$@"
else
	# Check for some basic commands, this is used to allow easy calling without
	# having to prepend the binary all the time.
	case "${1}" in
		help|serve|version)
			set -- ${EXE} "$@"
			;;
	esac
fi

# Setup environment.
setup_env() {
	[ -f /etc/defaults/docker-env ] && source /etc/defaults/docker-env
}
setup_env

# Support additional args provided via environment.
if [ -n "${ARGS}" ]; then
	set -- "$@" ${ARGS}
fi

# Run the service.
exec "$@"
