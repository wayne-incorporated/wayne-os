#!/bin/bash
#
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This will upload the mk_payload binary in the mirror which will be downloaded
# and installed by the ebuild and used by CrOS builders.
#
# You should run this script whenever there are changes to mk_payload. Such
# changes should be rare but if that changes it would be worthwhile to automate
# this process.

set -e

if [[ -z "$1" || -z "$2" ]]; then
  echo 'Usage: ./gather.sh <path_to_mk_payload> <version>'
  echo '  version should correspond to the ebuild version the binary will be'
  echo '  used with. For example, if we are upreving to 0.0.4, this should'
  echo '  be 0.0.4.'
  exit 1
fi

TMP_FILE=$(mktemp)
gzip -c "$1" > "${TMP_FILE}"

PACKET_VERSION="$2"
GCS_PATH='gs://chromeos-localmirror/distfiles/'
GCS_PATH+="mk-payload-${PACKET_VERSION}.gz"
if gsutil ls "${GCS_PATH}" &> /dev/null; then
  echo "${GCS_PATH} already exists!"
  echo 'If you want to delete it then run'
  echo "    gsutil rm ${GCS_PATH}"
  exit 1
fi
gsutil cp -n -a public-read "${TMP_FILE}" "${GCS_PATH}"

echo "Success! File was uploaded to ${GCS_PATH}"

rm "${TMP_FILE}"
