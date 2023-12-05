# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# BUILD_LIBRARY_DIR must be set prior to sourcing this file, since this file
# is sourced as ${BUILD_LIBRARY_DIR}/disk_layout_util.sh
# shellcheck source=filesystem_util.sh
. "${BUILD_LIBRARY_DIR}/filesystem_util.sh" || exit 1

# shellcheck disable=SC2154
CGPT_PY="${GCLIENT_ROOT}/chromite/scripts/disk_layout_tool"
# shellcheck disable=SC2034
PARTITION_SCRIPT_PATH="usr/sbin/write_gpt.sh"
DISK_LAYOUT_PATH=

cgpt_py() {
  if [[ -n "${FLAGS_adjust_part-}" ]]; then
    set -- --adjust_part "${FLAGS_adjust_part}" "$@"
    if [[ ! -t 0 ]]; then
      warn "The --adjust_part flag was passed." \
           "This option must ONLY be used interactively. If" \
           "you need to pass a size from another script, you're" \
           "doing it wrong and should be using a disk layout type."
    fi
  fi
  "${CGPT_PY}" "$@"
}

get_disk_layout_path() {
  if [[ -n ${DISK_LAYOUT_PATH} ]]; then
    return 0
  fi
  DISK_LAYOUT_PATH="${BUILD_LIBRARY_DIR}/legacy_disk_layout.json"
  local overlay
  for overlay in ${BOARD_OVERLAY}; do
    local disk_layout="${overlay}/scripts/disk_layout.json"
    if [[ -e ${disk_layout} ]]; then
      DISK_LAYOUT_PATH=${disk_layout}
    fi
  done
}

write_partition_script() {
  local image_type="$1"
  local partition_script_path="$2"
  local adjust_part="$3"
  get_disk_layout_path

  local part_vars
  part_vars="$(dirname "${partition_script_path}")/partition_vars.json"

  local temp_script_file
  local temp_vars_file
  temp_script_file=$(mktemp)
  temp_vars_file=$(mktemp)

  sudo mkdir -p "$(dirname "${partition_script_path}")"
  cgpt_py ${adjust_part:+--adjust_part "${adjust_part}"} \
          write "${image_type}" "${DISK_LAYOUT_PATH}" \
          "${temp_script_file}" "${temp_vars_file}"
  sudo mv "${temp_script_file}" "${partition_script_path}"
  sudo mv "${temp_vars_file}" "${part_vars}"
  sudo chmod a+r "${partition_script_path}"
  sudo chmod a+r "${part_vars}"
}

run_partition_script() {
  local outdev=$1
  local partition_script=$2

  local pmbr_img
  case ${ARCH} in
  amd64|x86)
    pmbr_img=$(readlink -f /usr/share/syslinux/gptmbr.bin)
    ;;
  *)
    pmbr_img=/dev/zero
    ;;
  esac

  . "${partition_script}"
  write_partition_table "${outdev}" "${pmbr_img}"
}

get_fs_block_size() {
  get_disk_layout_path

  cgpt_py readfsblocksize "${DISK_LAYOUT_PATH}"
}

get_block_size() {
  get_disk_layout_path

  cgpt_py readblocksize "${DISK_LAYOUT_PATH}"
}

get_image_types() {
  get_disk_layout_path

  cgpt_py readimagetypes "${DISK_LAYOUT_PATH}"
}

get_partition_size() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readpartsize "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_filesystem_format() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readfsformat "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_filesystem_options() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readfsoptions "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_format() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readformat "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_partitions() {
  local image_type=$1
  get_disk_layout_path

  cgpt_py readpartitionnums "${image_type}" "${DISK_LAYOUT_PATH}"
}

get_uuid() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readuuid "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_type() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readtype "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_filesystem_size() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readfssize "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_label() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readlabel "${image_type}" "${DISK_LAYOUT_PATH}" "${part_id}"
}

get_image_partition_number() {
  local image="$1"
  local label="$2"
  local part=$("${GPT}" find -n -l "${label}" "${image}")
  echo "${part}"
}

get_layout_partition_number() {
  local image_type=$1
  local part_label=$2
  get_disk_layout_path

  cgpt_py readnumber "${image_type}" "${DISK_LAYOUT_PATH}" "${part_label}"
}

get_reserved_erase_blocks() {
  local image_type=$1
  local part_id=$2
  get_disk_layout_path

  cgpt_py readreservederaseblocks "${image_type}" "${DISK_LAYOUT_PATH}" \
    ${part_id}
}

check_valid_layout() {
  local image_type=$1
  get_disk_layout_path

  cgpt_py validate "${image_type}" "${DISK_LAYOUT_PATH}" > /dev/null
}

get_disk_layout_type() {
  DISK_LAYOUT_TYPE="base"
  if should_build_image ${CHROMEOS_FACTORY_INSTALL_SHIM_NAME}; then
    DISK_LAYOUT_TYPE="factory_install"
  fi
}

emit_gpt_scripts() {
  local image="$1"
  local dir="$2"

  local pack="${dir}/pack_partitions.sh"
  local unpack="${dir}/unpack_partitions.sh"
  local mount="${dir}/mount_image.sh"
  local umount="${dir}/umount_image.sh"

  local start size part x

  local default

  # Write out the header for the script.
  local gpt_layout=$(${GPT} show "${image}" | sed -e 's/^/# /')
  for x in "${unpack}" "${pack}" "${mount}"; do
    cat >"${x}" <<\EOF
#!/bin/bash -eu
# File automatically generated. Do not edit.

usage() {
  local ret=0
  if [[ $# -gt 0 ]]; then
    # Write to stderr on errors.
    exec 1>&2
    echo "ERROR: $*"
    echo
    ret=1
  fi
  echo "Usage: $0 [-h|--help] [--nolosetup] [image] [part]"
  echo "Example: $0 chromiumos_image.bin"
  exit ${ret}
}

USE_LOSETUP=yes
TARGET=""
PART=""
ARG_INDEX=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      ;;
    --nolosetup)
      USE_LOSETUP=no
      shift
      ;;
    *)
      if [[ ${ARG_INDEX} -eq 0 ]]; then
        TARGET="${1}"
      elif [[ ${ARG_INDEX} -eq 1 ]]; then
        PART="${1}"
      else
        usage "too many arguments"
      fi
      ARG_INDEX=$((ARG_INDEX+1))
      shift
      ;;
  esac
done

case ${TARGET} in
"")
  for TARGET in chromiumos_{,base_}image.bin ""; do
    if [[ -e ${TARGET} ]]; then
      echo "autodetected image: ${TARGET}"
      break
    fi
  done
  if [[ -z ${TARGET} ]]; then
    usage "could not autodetect an image"
  fi
  ;;
*)
  if [[ ! -e ${TARGET} ]]; then
    usage "image does not exist: ${TARGET}"
  fi
esac

EOF

    if [[ "${x}" == "${pack}" || "${x}" == "${unpack}" ]]; then
      cat >>"${x}" <<\EOF
echo
echo "WARNING: $0 is deprecated and will be removed."
echo "WARNING: If you rely on this script, please email go/cros-build-help."
echo "NB: You can use losetup to efficiently access partitions:"
echo "    losetup --show -f -P ${TARGET}"
echo
sleep 1
EOF
    fi

    cat >>"${x}" <<\EOF
# Losetup has support for partitions, and offset= has issues.
# See crbug.com/954188
LOOPDEV=''
cleanup() {
  if [[ -n "${LOOPDEV}" ]]; then
    sudo losetup -d "${LOOPDEV}"
  fi
}
trap cleanup EXIT
if [[ "${USE_LOSETUP}" == yes ]]; then
  LOOPDEV=$(sudo losetup -P -f --show "${TARGET}") || exit 1
fi

EOF

    echo "${gpt_layout}" >> "${x}"
  done

  # Read each partition and generate code for it.
  while read start size part x; do
    local file="part_${part}"
    local dir="dir_${part}"
    local target='"${TARGET}"'
    local dd_args="bs=512 count=${size}"
    local start_b=$(( start * 512 ))
    local size_b=$(( size * 512 ))
    local label=$(${GPT} show "${image}" -i ${part} -l)

    for x in "${unpack}" "${pack}" "${mount}"; do
      cat <<EOF >> "${x}"
case \${PART:-${part}} in
${part}|"${label}")
EOF
    done

    cat <<EOF >> "${unpack}"
if [[ -n "\${LOOPDEV}" ]]; then
  sudo dd if="\${LOOPDEV}p${part}" of="${file}"
else
  dd if=${target} of="${file}" ${dd_args} skip=${start}
fi
ln -sfT ${file} "${file}_${label}"
EOF
    cat <<EOF >> "${pack}"
if [[ -n "\${LOOPDEV}" ]]; then
  sudo dd if="${file}" of="\${LOOPDEV}p${part}"
else
  dd if="${file}" of=${target} ${dd_args} seek=${start} conv=notrunc
fi
EOF

    if [[ ${size} -gt 1 ]]; then
      cat <<-EOF >>"${mount}"
(
mkdir -p "${dir}"
m=( sudo mount "\${LOOPDEV}p${part}" "${dir}" )
if ! "\${m[@]}"; then
  if ! "\${m[@]}" -o ro; then
    rmdir ${dir}
    exit 0
  fi
fi
ln -sfT ${dir} "${dir}_${label}"
) &
EOF
    fi

    for x in "${unpack}" "${pack}" "${mount}"; do
      echo "esac" >> "${x}"
    done
  done < <(${GPT} show -q "${image}")

  echo "wait" >> "${mount}"

  cp "${BUILD_LIBRARY_DIR}/umount_image_helper.sh" "${umount}"

  chmod +x "${unpack}" "${pack}" "${mount}" "${umount}"
}

# Usage: mk_fs  <image_file> <image_type> <partition_num>
# Args:
#   image_file: The image file.
#   image_type: The layout name used to look up partition info in disk layout.
#   partition_num: The partition number to look up in the disk layout.
#
# Note: After we mount the fs, we will attempt to reset the root dir ownership
#       to 0:0 to workaround a bug in mke2fs (fixed in upstream git now).
mk_fs() {
  local image_file=$1
  local image_type=$2
  local part_num=$3

  # These are often not in non-root $PATH, but they contain tools that
  # we can run just fine w/non-root users when we work on plain files.
  local p
  for p in /sbin /usr/sbin; do
    if [[ ":${PATH}:" != *:${p}:* ]]; then
      PATH+=":${p}"
    fi
  done

  # Keep `local` decl split from assignment so return code is checked.
  local fs_bytes fs_label fs_format fs_options fs_block_size offset fs_type
  fs_format=$(get_filesystem_format ${image_type} ${part_num})
  fs_options="$(get_filesystem_options ${image_type} ${part_num})"
  if [ -z "${fs_format}" ]; then
    # We only make fs for partitions that specify a format.
    return 0
  fi

  fs_bytes=$(get_filesystem_size ${image_type} ${part_num})
  fs_block_size=$(get_fs_block_size)
  if [ "${fs_bytes}" -le ${fs_block_size} ]; then
    # Skip partitions that are too small.
    info "Skipping partition ${part_num} as the blocksize is too small."
    return 0
  fi

  info "Creating FS for partition ${part_num} with format ${fs_format}."

  fs_label=$(get_label ${image_type} ${part_num})
  fs_uuid=$(get_uuid ${image_type} ${part_num})
  fs_type=$(get_type ${image_type} ${part_num})

  # Root is needed to mount on loopback device.
  # sizelimit is used to denote the FS size for mkfs if not specified.
  local image_dev
  image_dev=$(loopback_partscan "${image_file}")
  local part_dev=${image_dev}p${part_num}
  if [ ! -e "${part_dev}" ]; then
    die "No free loopback device to create partition."
  fi

  fs_create "${fs_uuid}" "${fs_label}" "${fs_bytes}" "${fs_block_size}" \
      "${fs_format}" "${fs_options}" "${part_dev}"

  local mount_dir="$(mktemp -d)"
  local cmds=(
    # mke2fs is funky and sets the root dir owner to current uid:gid.
    "chown 0:0 '${mount_dir}' 2>/dev/null || :"
  )

  # Prepare partitions with well-known mount points.
  if [ "${fs_label}" = "STATE" ]; then
    # These directories are used to mount data from stateful onto the rootfs.
    cmds+=("sudo mkdir '${mount_dir}/dev_image'"
           "sudo mkdir '${mount_dir}/var_overlay'"
    )
  elif [ "${fs_type}" = "rootfs" ]; then
    # These rootfs mount points are necessary to mount data from other
    # partitions onto the rootfs. These are used by both build and run times.
    cmds+=("sudo mkdir -p '${mount_dir}/mnt/stateful_partition'"
           "sudo mkdir -p '${mount_dir}/usr/local'"
           "sudo mkdir -p '${mount_dir}/usr/share/oem'"
           "sudo mkdir '${mount_dir}/var'"
    )
  fi
  fs_mount "${part_dev}" "${mount_dir}" "${fs_format}" "rw"
  sudo_multi "${cmds[@]}"
  fs_umount "${part_dev}" "${mount_dir}" "${fs_format}" "${fs_options}"
  fs_remove_mountpoint "${mount_dir}"
  sudo losetup -d ${image_dev}
}

# Creates the gpt image for the given disk layout. In addition to creating
# the partition layout it creates all the initial filesystems. After this file
# is created, mount_gpt_image.sh can be used to mount all the filesystems onto
# directories.
build_gpt_image() {
  local outdev="$1"
  local disk_layout="$2"

  # Build the partition table and partition script.
  local partition_script_path
  partition_script_path="$(dirname "${outdev}")/partition_script.sh"
  write_partition_script "${disk_layout}" "${partition_script_path}"
  run_partition_script "${outdev}" "${partition_script_path}"

  # Emit the gpt scripts so we can use them from here on out.
  emit_gpt_scripts "${outdev}" "$(dirname "${outdev}")"

  # Create the filesystem on each partition defined in the layout file.
  local p
  for p in $(get_partitions "${disk_layout}"); do
    mk_fs "${outdev}" "${disk_layout}" "${p}"
  done

  # Pre-set "sucessful" bit in gpt, so we will never mark-for-death
  # a partition on an SDCard/USB stick.
  cgpt add -i $(get_layout_partition_number "${disk_layout}" KERN-A) -S 1 \
    "${outdev}"
}

round_up_4096() {
  local blocks=$1
  local round_up=$(( blocks % 4096 ))
  if [ $round_up -ne 0 ]; then
    blocks=$(( blocks + 4096 - round_up ))
  fi
  echo $blocks
}

# Rebuild an image's partition table with new stateful size.
#  $1: source image filename
#  $2: source stateful partition image filename
#  $3: number of sectors to allocate to the new stateful partition
#  $4: destination image filename
# Used by dev/host/tests/mod_recovery_for_decryption.sh and
# mod_image_for_recovery.sh.
update_partition_table() {
  local src_img=$1              # source image
  local src_state=$2            # stateful partition image
  local dst_stateful_blocks=$3  # number of blocks in resized stateful partition
  local dst_img=$4

  rm -f "${dst_img}"

  # Find partition number of STATE.
  local part=0
  local label=""
  while [ "${label}" != "STATE" ]; do
    part=$(( part + 1 ))
    local label=$(cgpt show -i ${part} -l ${src_img})
    local src_start=$(cgpt show -i ${part} -b ${src_img})
    if [ ${src_start} -eq 0 ]; then
      echo "Could not find 'STATE' partition" >&2
      return 1
    fi
  done

  # Make sure new stateful's size is a multiple of 4096 blocks so that
  # relocated partitions following it are not misaligned.
  dst_stateful_blocks=$(round_up_4096 $dst_stateful_blocks)
  # Calculate change in image size.
  local src_stateful_blocks=$(cgpt show -i ${part} -s ${src_img})
  local delta_blocks=$(( dst_stateful_blocks - src_stateful_blocks ))
  local dst_stateful_bytes=$(( dst_stateful_blocks * 512 ))
  local src_stateful_bytes=$(( src_stateful_blocks * 512 ))
  local src_size=$(stat -c %s ${src_img})
  local dst_size=$(( src_size - src_stateful_bytes + dst_stateful_bytes ))
  truncate -s ${dst_size} ${dst_img}

  # Copy MBR, initialize GPT.
  dd if="${src_img}" of="${dst_img}" conv=notrunc bs=512 count=1 status=none
  cgpt create ${dst_img}

  local src_state_start=$(cgpt show -i ${part} -b ${src_img})

  # Duplicate each partition entry.
  part=0
  while :; do
    part=$(( part + 1 ))
    local src_start=$(cgpt show -i ${part} -b ${src_img})
    if [ ${src_start} -eq 0 ]; then
      # No more partitions to copy.
      break
    fi
    local dst_start=${src_start}
    # Load source partition details.
    local size=$(cgpt show -i ${part} -s ${src_img})
    local label=$(cgpt show -i ${part} -l ${src_img})
    local attr=$(cgpt show -i ${part} -A ${src_img})
    local tguid=$(cgpt show -i ${part} -t ${src_img})
    local uguid=$(cgpt show -i ${part} -u ${src_img})
    if [[ ${size} -eq 0 ]]; then
      continue
    fi
    # Change size of stateful.
    if [ "${label}" = "STATE" ]; then
      size=${dst_stateful_blocks}
    fi
    # Partitions located after STATE need to have their start moved.
    if [ ${src_start} -gt ${src_state_start} ]; then
      dst_start=$(( dst_start + delta_blocks ))
    fi
    # Add this partition to the destination.
    cgpt add -i ${part} -b ${dst_start} -s ${size} -l "${label}" -A ${attr} \
             -t ${tguid} -u ${uguid} ${dst_img}
    if [ "${label}" != "STATE" ]; then
      # Copy source partition as-is.
      dd if="${src_img}" of="${dst_img}" conv=notrunc bs=512 \
        skip=${src_start} seek=${dst_start} count=${size} status=none
    else
      # Copy new stateful partition into place.
      dd if="${src_state}" of="${dst_img}" conv=notrunc bs=512 \
        seek=${dst_start} status=none
    fi
  done
  return 0
}
