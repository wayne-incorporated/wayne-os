#!/bin/bash
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CURRENT_DIR="$(dirname "$(readlink -f "$0")")"
SCRIPT_ROOT="${CURRENT_DIR}/../../scripts"
# shellcheck source=../../scripts/common.sh
. "${SCRIPT_ROOT}/common.sh" || exit 1

# Lookup table for default firmware version for RO.
# Should give 2.2.64 for nocturne, 2.2.144 for nami.
BOARD_TO_FACTORY_RO_VERSION="\
nocturne 10984.21.0
nami 10984.82.0"

DEFINE_string board "" "The board name. e.g. nocturne" b
DEFINE_string ro_version "" \
  "The firmware version of the target file for RO part. e.g. 10984.88.0" r
DEFINE_string rw_version "" \
  "The firmware version of the target file for RW part. e.g. 10984.88.0" w
DEFINE_string channel "dev" \
  "The channel of the target file. One of canary, dev, beta, or stable" c

FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

set -e

# The temporary working directory.
TMP=""
# The base URL of the downloaded files (RO version).
GS_URL_BASE_RO=""
# The base URL of the downloaded files (RW version).
GS_URL_BASE_RW=""
# The directory on gs containing the required firmware binaries.
# This can be different from the board name, e.g. board "nami" is in directory
# "nocturne".
DIRECTORY_NAME=""
# Version number of RO part of FP firmware
FP_RO_VERSION_NUMBER=""
# Version number of RW part of FP firmware
FP_RW_VERSION_NUMBER=""
# Name of final output file
OUTPUT_TAR=""

get_fw_version_for_RO() {
  local board_name="${1}"
  local key
  local value
  echo "${BOARD_TO_FACTORY_RO_VERSION}" | while read -r key value; do
    if [[ "${key}" == "${board_name}" ]]; then
      echo "${value}"
    fi
  done
}

# verify_mp (file): Verify that |file| is signed by mp key.
verify_mp() {
  local file="$1"
  local version
  version="$(futility verify "${file}" \
    | grep "Version:" \
    | grep -o "0x0000000[0-9]")"
  local expected
  # Key versions for nocturne were different but it was a 1-off and should not
  # happen again.
  if [[ "${FLAGS_board}" == "nocturne" ]]; then
    expected="0x00000002"
  else
    expected="0x00000003"
  fi

  if [[ "${version}" != "${expected}" ]]; then
    die "${file} may not be signed with mp key! Key version: ${version}."
  fi
}

init() {
  TMP="$(mktemp -d)"
  echo "Create temp work directory: ${TMP}"
  cd "${TMP}"

  if [[ -z "${FLAGS_board}" ]]; then
    die_notrace "Please specify the board name using -b"
  fi

  if [[ -z "${FLAGS_ro_version}" ]]; then
    FLAGS_ro_version="$(get_fw_version_for_RO "${FLAGS_board}")"
    if [[ -z "${FLAGS_ro_version}" ]]; then
      die_notrace \
      "Please specify a firmware version for RO part using -r, e.g. 10984.88.0"
    fi
  fi

  if [[ -z "${FLAGS_rw_version}" ]]; then
    die_notrace \
    "Please specify a firmware version for RW part using -w, e.g. 10984.88.0"
  fi

  if [[ -z "${FLAGS_channel}" ]]; then
    die_notrace "Please specify a channel using -c, e.g. canary"
  fi

  # Due to historical reasons, the nami_fp firmware are put in nocturne
  # directory.
  if [[ "${FLAGS_board}" == "nami" ]]; then
    DIRECTORY_NAME="nocturne"
  else
    DIRECTORY_NAME="${FLAGS_board}"
  fi

  local gs_url_base="gs://chromeos-releases/${FLAGS_channel}-channel/\
${DIRECTORY_NAME}"

  GS_URL_BASE_RO="${gs_url_base}/${FLAGS_ro_version}"
  echo "Looking for RO part at URL: ${GS_URL_BASE_RO}"
  if ! gsutil ls "${GS_URL_BASE_RO}" > /dev/null; then
    die_notrace \
    "${GS_URL_BASE_RO} is not a valid URL. Please check the argument."
  fi

  GS_URL_BASE_RW="${gs_url_base}/${FLAGS_rw_version}"
  echo "Looking for RW part at URL: ${GS_URL_BASE_RW}"
  if ! gsutil ls "${GS_URL_BASE_RW}" > /dev/null; then
    die_notrace \
    "${GS_URL_BASE_RW} is not a valid URL. Please check the argument."
  fi
}

cleanup() {
  cd "${CURRENT_DIR}"
  if [[ ( -n "${TMP}" ) && ( -d "${TMP}" ) ]]; then
    rm -rf "${TMP}"
  fi
}

# get_ec_file_path (ro|rw): Get the full path to latest mp signed fp binary.
get_ec_file_path() {
  local image_type="$1"
  local version
  local url
  if [[ "${image_type}" == "ro" ]]; then
    version="${FLAGS_ro_version}"
    url="${GS_URL_BASE_RO}"
  else
    version="${FLAGS_rw_version}"
    url="${GS_URL_BASE_RW}"
  fi

  # Normally there should be only one mp signed fp firmware, but in case there
  # are more, sort by version.
  local file_name
  file_name="$(gsutil ls "${url}" \
    | grep -E "chromeos_${version}_${FLAGS_board}-fp_mp(-v[0-9]+)?.bin$" \
    | sort -V \
    | tail -n1)"

  if [[ -z "${file_name}" ]]; then
    die_notrace \
    "Cannot find any mp signed FP firmware for board ${FLAGS_board} at ${url}"
  fi

  echo "${file_name}"
}

process_ec_file() {
  local ec_ro="ec_ro.bin"
  local ec_rw="ec_rw.bin"

  # Download the two binaries as ec_ro.bin and ec_rw.bin.
  gsutil cp "$(get_ec_file_path ro)" "${ec_ro}" &> /dev/null
  gsutil cp "$(get_ec_file_path rw)" "${ec_rw}" &> /dev/null

  verify_mp "${ec_ro}"
  verify_mp "${ec_rw}"

  # Print RO and RW versions.
  local fmap_frid
  # shellcheck disable=SC2207
  fmap_frid=($(dump_fmap -p "${ec_ro}" RO_FRID))
  local fmap_fwid
  # shellcheck disable=SC2207
  fmap_fwid=($(dump_fmap -p "${ec_rw}" RW_FWID))
  # fmap_frid[0]="RO_FRID" fmap_frid[1]=offset fmap_frid[2]=size (decimal)
  # Same for fmap_fwid.
  local ro_version_string
  ro_version_string="$(dd bs=1 skip="${fmap_frid[1]}" \
    count="${fmap_frid[2]}" if="${ec_ro}" 2>/dev/null; echo)"
  local rw_version_string
  rw_version_string="$(dd bs=1 skip="${fmap_fwid[1]}" \
    count="${fmap_fwid[2]}" if="${ec_rw}" 2>/dev/null; echo)"

  echo "Using FP firmware RO version: ${ro_version_string}"
  echo "Using FP firmware RW version: ${rw_version_string}"

  FP_RO_VERSION_NUMBER="$(echo "${ro_version_string}" \
    | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+")"

  FP_RW_VERSION_NUMBER="$(echo "${rw_version_string}" \
    | grep -o -E "[0-9]+\.[0-9]+\.[0-9]+")"

  # Use RW firmware version as file name.
  local new_file="${rw_version_string}.bin"
  # fmap_rw_section[0]="EC_RW"
  # fmap_rw_section[1]=offset
  # fmap_rw_section[2]=size (decimal)
  local fmap_rw_section
  # shellcheck disable=SC2207
  fmap_rw_section=($(dump_fmap -p "${ec_ro}" EC_RW))

  # Inject RW into the existing RO file.
  echo "Merging files..."
  cp "${ec_ro}" "${new_file}"
  dd if="${ec_rw}" of="${new_file}" \
    bs=1 skip="${fmap_rw_section[1]}" seek="${fmap_rw_section[1]}" \
    count="${fmap_rw_section[2]}" conv=notrunc &> /dev/null

  # Verify the resulting image is signed properly.
  echo "Verifiying output file..."
  verify_mp "${new_file}"
  if ! futility verify --strict "${new_file}" >&2; then
    die "Cannot verify ${new_file}."
  fi

  echo "Merged into new binary: ${new_file}"
  OUTPUT_TAR="${FLAGS_board}_fp_${FP_RW_VERSION_NUMBER}.tbz2"
  tar jcf "${OUTPUT_TAR}" "${new_file}"

  echo "Generating the FP firmware tarball: ${OUTPUT_TAR}"
  mv "${OUTPUT_TAR}" "${CURRENT_DIR}"
}

main() {
  TMP=""
  trap cleanup EXIT
  assert_inside_chroot
  init

  # Download and extract EC firmware.
  process_ec_file

  # Print out the update instruction.
  cat <<EOF
${V_BOLD_GREEN}Successfully generated the FPMCU EC tarball with RO version \
${FP_RO_VERSION_NUMBER} and RW version ${FP_RW_VERSION_NUMBER}.

Please upload the tarball ${OUTPUT_TAR} to CPFE and update the corresponding \
ebuild.
${V_VIDOFF}
EOF
}

main "$@"
