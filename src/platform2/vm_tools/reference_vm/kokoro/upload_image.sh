#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -eux -o pipefail

main() {
  # shellcheck disable=SC2154
  cd "${KOKORO_GFILE_DIR}"
  images=(*/*.br)
  if (( "${#images[@]}" != 1 )); then
    echo "More than 1 artifact found"
    exit 1
  fi

  image="${images[0]}"
  prefix="$(dirname "${image}")"
  dest_name="$(basename "${image}" .br)"
  gs_path="gs://refvm-images/${prefix}/${dest_name}"
  gsutil -h "Content-Encoding:br" cp "${image}" "${gs_path}"

  # TODO(b/286339260): Update tast-tests with new image path and SHA256.
}

main "$@"
