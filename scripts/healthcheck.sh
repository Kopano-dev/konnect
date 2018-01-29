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

# Get listener address from system.
LISTENER="$(netstat -nplt 2>/dev/null | grep "${EXE}" | awk ' // { gsub(":::", "127.0.0.1:", $4); print $4 }' | tail -n1)"
if [ -z "${LISTENER}" ]; then
	exit 1
fi

# Check with wget as it is a part of busybox.
exec wget -SO- http://${LISTENER}/health-check 2>&1 | grep -q '200 OK'
