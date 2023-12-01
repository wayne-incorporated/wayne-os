#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script is used to generate the firmware tarball. After generating the
# tarball, please upload the tarball by running:
#   $ gsutil cp <tarball>.tbz2 gs://chromeos-localmirror/distfiles/
# And then update chromeos-firmware-<base> ebuild file.

CURRENT_DIR="$(dirname "$(readlink -f "$0")")"
SCRIPT_ROOT="${CURRENT_DIR}/../../scripts"
. "${SCRIPT_ROOT}/common.sh" || exit 1

# The mapping from the board name and the base name. We only support the boards
# listed here.
BOARD_LOOKUP_TABLE="\
poppy wand
soraka staff
meowth whiskers
nocturne whiskers"

DEFINE_string board "" "The board name. e.g. poppy" b
DEFINE_string ro_version "" "The RO version of the target file. e.g. 9790.0.0" r
DEFINE_string rw_version "" "The RW version of the target file. e.g. 9794.0.0" v
DEFINE_string channel "dev" \
  "The channel of the target file. One of canary, dev, beta, or stable" c
DEFINE_string signed_key "dev" \
  "The signed key of the target file. e.g. dev, premp, premp-v2, mp, mp-v2" s
DEFINE_string detachable_base_name "" \
  "The detachable base name. e.g. masterball" d
DEFINE_boolean skip_touchpad_binary "${FLAGS_FALSE}" \
  "Set if the touchpad binary is not required" k

FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

set -e

# Global variables that are assigned in init() function.
# The temporary working directory.
TMP=""
# The base URL of the downloaded files (RO version).
GS_URL_BASE_RO=""
# The base URL of the downloaded files (RW version).
GS_URL_BASE_RW=""
# The detachable base code name.
BASE_NAME=""

get_base_name() {
  local board_name="${1}"
  local key
  local value
  echo "${BOARD_LOOKUP_TABLE}" | while read key value; do
    if [[ "${key}" == "${board_name}" ]]; then
      echo "${value}"
    fi
  done
}

init() {
  TMP="$(mktemp -d)"
  echo "Create temp work directory: ${TMP}"
  cd "${TMP}"

  if [[ -z "${FLAGS_board}" ]]; then
    die_notrace "Please specify the board name using -b"
  fi

  BASE_NAME="$(get_base_name "${FLAGS_board}")"
  if [[ -n "${FLAGS_detachable_base_name}" ]]; then
    if [[ -n "${BASE_NAME}" ]]; then
      die_notrace "Can't specify base name for non-unibuild project"
    fi
    BASE_NAME="${FLAGS_detachable_base_name}"
  fi

  if [[ -z "${BASE_NAME}" ]]; then
    die_notrace "The board name is not supported." \
      "Please specify the detachable base name using -d for unibuild project."
  fi
  echo "The base name: ${BASE_NAME}"

  if [[ -z "${FLAGS_ro_version}" ]]; then
    die_notrace "Please specify a firmware RO version using -r, e.g. 9794.0.0"
  fi

  if [[ -z "${FLAGS_rw_version}" ]]; then
    die_notrace "Please specify a firmware RW version using -v, e.g. 9790.0.0"
  fi

  if [[ -z "${FLAGS_channel}" ]]; then
    die_notrace "Please specify a channel using -c, e.g. canary"
  fi

  if [[ "${FLAGS_signed_key}" != "dev" ]] &&
     [[ "${FLAGS_signed_key}" != premp* ]] &&
     [[ "${FLAGS_signed_key}" != mp* ]]; then
    die_notrace "Please specify a signed key name using -s, e.g. dev, premp, mp"
  fi

  local gs_url_base="gs://chromeos-releases/${FLAGS_channel}-channel/${FLAGS_board}"
  GS_URL_BASE_RO="${gs_url_base}/${FLAGS_ro_version}"
  if ! gsutil ls "${GS_URL_BASE_RO}" > /dev/null; then
    die_notrace "${GS_URL_BASE_RO} is not a valid URL. Please check the argument."
  fi

  GS_URL_BASE_RW="${gs_url_base}/${FLAGS_rw_version}"
  if ! gsutil ls "${GS_URL_BASE_RW}" > /dev/null; then
    die_notrace "${GS_URL_BASE_RW} is not a valid URL. Please check the argument."
  fi
}

cleanup() {
  cd "${CURRENT_DIR}"
  rm -rf "${TMP}"
}

# get_ec_file_name (ro|rw): Get file name for the EC binary/tarball (using RO or
# RW version depending on parameter).
get_ec_file_name() {
  if [[ "${FLAGS_signed_key}" == "dev" ]]; then
    echo "ChromeOS-firmware-*.tar.bz2"
  else
    if [[ "$1" == "ro" ]]; then
      echo "chromeos_${FLAGS_ro_version}_${BASE_NAME}_${FLAGS_signed_key}.bin"
    else
      echo "chromeos_${FLAGS_rw_version}_${BASE_NAME}_${FLAGS_signed_key}.bin"
    fi
  fi
}

get_tp_tarball_name() {
  echo "ChromeOS-accessory_rwsig-*-${FLAGS_rw_version}-${FLAGS_board}.tar.bz2"
}

# download_file (ro|rw) filename: Download a file that may have wildcard from
# either RO or RW version folder in GS, and return the exact file name.
download_file() {
  local base
  if [[ "$1" == "ro" ]]; then
    base="${GS_URL_BASE_RO}"
  else
    base="${GS_URL_BASE_RW}"
  fi
  local gs_url="${base}/${2}"
  local fw_path="$(gsutil ls "${gs_url}")"
  if [[ -z "${fw_path}" ]]; then
    die "Please ensure your gsutil works and the firmware version is correct."
  fi
  gsutil cp "${fw_path}" . > /dev/null

  echo "$(basename "${fw_path}")"
}

# Extract EC file from downloaded file ($1) to specified location ($2).
extract_ec_file() {
  local ec_path="${BASE_NAME}/ec.bin"

  # If the firmware is signed, then the downloaded file is the binary blob,
  # instead of a tarball.
  if [[ "${1}" == *.bin ]]; then
    mv "${1}" "${2}"
  else
    tar xf "${1}" "${ec_path}"
    mv "${ec_path}" "${2}"
  fi
}

process_ec_file() {
  local ec_ro="ec_ro.bin"
  local ec_rw="ec_rw.bin"

  extract_ec_file "$(download_file ro "$(get_ec_file_name ro)")" "${ec_ro}"
  extract_ec_file "$(download_file rw "$(get_ec_file_name rw)")" "${ec_rw}"

  # Use RW firmware version as file name.
  local fw_version_rw="$(strings "${ec_rw}" | grep "${BASE_NAME}" | head -n1)"
  local new_file="${fw_version_rw}.fw"
  # fmap[0]="EC_RW" fmap[1]=offset fmap[2]=size (decimal)
  local fmap=($(dump_fmap -p "${ec_ro}" EC_RW))

  # Inject RW into the existing RO file.
  cp "${ec_ro}" "${new_file}"
  dd if="${ec_rw}" of="${new_file}" \
     bs=1 skip="${fmap[1]}" seek="${fmap[1]}" count="${fmap[2]}" conv=notrunc

  # Verify the resulting image is signed properly.
  if ! futility verify --strict "${new_file}" >&2; then
    die "Cannot verify ${new_file}."
  fi

  echo "${new_file}"
}

process_tp_file() {
  local real_file_name
  if [[ "${FLAGS_skip_touchpad_binary}" == "${FLAGS_TRUE}" ]]; then
    return
  fi
  local downloaded_file
  downloaded_file="$(download_file rw "$(get_tp_tarball_name)")"

  # Extract the symbolic link first, then extract the target file.
  local sym_file_name="touchpad.bin"
  tar xf "${downloaded_file}" "${BASE_NAME}/${sym_file_name}"
  real_file_name="$(readlink "${BASE_NAME}/${sym_file_name}")"
  tar xf "${downloaded_file}" "${BASE_NAME}/${real_file_name}"
  mv "${BASE_NAME}/${real_file_name}" "${real_file_name}"
  echo "${real_file_name}"
}

main() {
  TMP=""
  trap cleanup EXIT
  init

  local ec_file
  local tp_file
  local tar_args

  # Download and extract EC firmware and touchpad firmware.
  ec_file="$(process_ec_file)"
  tp_file="$(process_tp_file)"
  # Pack EC and touchpad firmware and move to the current directory.
  local output_tar="${BASE_NAME}_${FLAGS_ro_version}-${FLAGS_rw_version}_${FLAGS_signed_key}.tbz2"
  tar_args=()
  tar_args+=("${ec_file}")
  if [[ -n "${tp_file}" ]]; then
    tar_args+=("${tp_file}")
  fi
  tar jcf "${output_tar}" "${tar_args[@]}"
  mv "${output_tar}" "${CURRENT_DIR}"

  # Print out the update instruction.
  cat <<EOF
${V_BOLD_GREEN}
Successfully generated the EC and touchpad firmware tarball! ${V_VIDOFF}

For the unibuild project:
  1. Put the detachable base firmware binary to
     overlay-${FLAGS_board}-private/chromeos-base/\
chromeos-bsp-${FLAGS_board}-private/files/detachable_base/\
firmware/${BASE_NAME}.bin
  2. If the detachable base has the touchpd
     a. Put the touchpad firmware binary to
        overlay-${FLAGS_board}-private/chromeos-base/\
chromeos-bsp-${FLAGS_board}-private/files/detachable_base/\
touch/${tp_file}.bin
     b. Modify the ebuild overlay-${FLAGS_board}-private/\
chromeos-base/chromeos-bsp-${FLAGS_board}-private/\
chromeos-bsp-${FLAGS_board}-private-0.0.1.ebuild

For the non-unibuild project, \
follow the below steps to upload the EC firmware tarball:
  1. Go to CPFE and Click "Uploads - Private"
  2. Select the tarball file at "Select Component File"
  3. Select "overlay-${FLAGS_board}-private" overlay
  4. Enter "chromeos-base/chromeos-firmware-${BASE_NAME}" in \
"Relative path to file"
  5. Update the variables of "chromeos-firmware-${BASE_NAME}" ebuild file.

    FW_TARBALL="${output_tar}"
    EC_FW_NAME="${ec_file}"
    TP_FW_NAME="${tp_file}"
EOF
}

main "$@"
