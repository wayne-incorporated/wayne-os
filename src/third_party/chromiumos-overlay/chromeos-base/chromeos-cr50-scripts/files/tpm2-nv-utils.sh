#!/bin/sh
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Write-locks a given nv space index. The index is specified as the first input
# argument in a hex number, w/o "0x" prefix.
# Example usage: /usr/share/cros/tpm2-lock-space.sh 013fff00

TPM2_CC_NV_READ="0000014e"
TPM2_CC_NV_WRITE="00000137"
TPM2_CC_NV_WRITELOCK="00000138"

cmd="$1"
index="$2"

if [ -z "${cmd}" ]; then
  >&2 echo "No command specified"
  exit 1
fi

cmd_param=""

case "${cmd}" in
  read)
    tpm_cc="${TPM2_CC_NV_READ}"
    data_len="$3"
    if [ -z "${data_len}" ]; then
      >&2 echo "No length specified"
      exit 1
    fi
    if [ $((data_len)) -gt 4096 ]; then
      >&2 echo "nv size too large"
      exit 1
    fi
    data_len_hex="$(printf '%04x' "${data_len}")"
    # size of offset, both in UNIT16
    cmd_param="${data_len_hex}0000"
    ;;
  write)
    tpm_cc="${TPM2_CC_NV_WRITE}"
    data="$3"
    if [ -z "${data}" ]; then
      >&2 echo "No data to write"
      exit 1
    fi
    # 4096 is an arbitrary upper bound that is supposed to much larger than a nv
    # index size in practice.
    if [ ${#data} -gt 4096 ]; then
      >&2 echo "data to write too long"
      exit 1
    fi
    data_len=$(( ${#data} / 2 ))
    data_len_hex="$(printf '%04x' "${data_len}")"
    # TPM2B_MAX_NV_BUFFER, and offset in UINT16.
    cmd_param="${data_len_hex}${data}0000"
    ;;
  writelock)
    tpm_cc="${TPM2_CC_NV_WRITELOCK}"
    # No extra parameter.
    ;;
  *)
    >&2 echo "Command not support: ${cmd}"
    exit 1
esac

# Choose a tool for sending raw TPM commands
if pidof trunksd > /dev/null; then
  # trunksd is running
  send_util="trunks_send --raw"
else
  # trunksd is stopped
  send_util="tpmc raw"
fi

# A 8-byte place holder of the command size, which is calculated after the full
# command is composed so the size is known.
CMD_SIZE_PLACE_HOLDER="CMD_SIZE"

tpm_cmd="80 02 ${CMD_SIZE_PLACE_HOLDER} ${tpm_cc} ${index} ${index} \
         00 00 00 09 40 00 00 09 00 00 00 00 00 ${cmd_param}"

# Re-format tpm_cmd into space-splitted hex pairs in order to be
# tpmc-compatible. Also, substitute the placeholder of command size.

# First, remove space from the tpm_cmd.
tpm_cmd="$(echo "${tpm_cmd}" | sed -e "s/ //g")"
# Calculate the size and format it in 8-digit hex.
tpm_cmd_len=$(( ${#tpm_cmd} / 2 ))
tpm_cmd_len_hex="$(printf '%08x' "${tpm_cmd_len}")"
# Replace the command size.
tpm_cmd="$(echo "${tpm_cmd}" | \
           sed -e "s/${CMD_SIZE_PLACE_HOLDER}/${tpm_cmd_len_hex}/g")"
#Format it in space-separated hex pair.
tpm_cmd="$(echo "${tpm_cmd}" | fold -w2 | paste -sd' ')"


output="$(${send_util} "${tpm_cmd}")" || exit 1
response="$(echo "${output}" | sed -e 's/0x//g' | \
            tr -d ' \n' | tr '[:upper:]' '[:lower:]')"

# Check response code in header.
hdr="$(echo "${response}" | cut -b 13-20)"
TPM_SUCCESS="00000000"
if [ "${hdr}" != "${TPM_SUCCESS}" ]; then
  >&2 echo "Unexpected response for ${cmd}: ${response}"
  exit 1
fi

# if it's TPM2_NV_Read, print the content.
if [ "${cmd}" = "read" ]; then
  output_data="$(echo "${response}" | cut -b 33- | cut -b -$(( data_len * 2 )) )"
  if [ ${#output_data} != $(( data_len * 2 )) ]; then
    >&2 echo "Unexpected output size of nv data: ${response}"
    exit 1
  fi
  echo "${output_data}"
fi

exit 0
