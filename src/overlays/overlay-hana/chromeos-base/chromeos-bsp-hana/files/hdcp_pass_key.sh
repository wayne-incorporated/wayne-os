#!/bin/sh
# Copyright (c) 2016 MediaTek Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

VPDDATA="/var/cache/vpd/full-v2.txt"
HDCP_NODE="/sys$1/hdcp_key"

log() {
  logger -t "hdcp-pass-key" -s "$@"
}

# check if the hdcp node exists or not
if [ ! -e "${HDCP_NODE}" ]; then
  log "hdcp node: \"${HDCP_NODE}\" doesn't exist"
  exit 1
fi

# Grab the hdcp_key from VPD.
# Below example is the hdcp_key data format in VPD. This is
# just an example, so the real key length will be longer.
# "hdcp_key"="balabalabalabalabalabalabalabala"
KEYSET=$(sed -n 's/"hdcp_key"="\(.*\)"/\1/p' "${VPDDATA}")

# check if KEYSET was found
if [ -n "${KEYSET}" ]; then
  log "read vpd key ok"
else
  log "read vpd key fail"
  exit 1
fi

# The 288-byte HDCP key set (40 7-byte keys, plus 8-bytes KSV) is passed
# to the Mediatek HDMI driver as a 664-byte encrypted blob.
# The VPD key "hdcp_key" stores this blob as a 886-byte base64 encoded string.
echo "${KEYSET}" | base64 -d | hexdump -n 664 -ve '/1 "%02x"' > "${HDCP_NODE}"
