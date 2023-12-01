#!/bin/sh
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

SWAP_ENABLE_FILE="/var/lib/swap/swap_enabled"
ZRAM_BACKING_DEV="/sys/block/zram0/backing_dev"
ZRAM_WRITEBACK_NAME="zram-writeback"
ZRAM_INTEGRITY_NAME="zram-integrity"
ZRAM_WRITEBACK_DEV_ENC="/dev/mapper/${ZRAM_WRITEBACK_NAME}"
ZRAM_WRITEBACK_INTEGRITY_MOUNT="/run/zram-integrity"
ZRAM_INTEGRITY_DEV="/dev/mapper/${ZRAM_INTEGRITY_NAME}"
LOOP_BLOCK_OPEN_PREFIX="__block_open_on_autoclear__"
STATEFUL_PARTITION_DIR="/mnt/stateful_partition/unencrypted/userspace_swap.tmp"
MB=1048576

# Never allow swapping to disk when the overall free diskspace is less
# than 15% of the overall capacity.
MIN_FREE_DISKSPACE_PCT=15

# Never allow more than 15% of the FREE diskspace to be used for swap.
MAX_PCT_OF_FREE_DISKSPACE=15

# We default to 1gb of writeback space.
DEFAULT_WRITEBACK_SIZE_MB=1024

# Don't allow more than 6GB to be configured.
MAX_ZRAM_WRITEBACK_SIZE_MB=6144

# Don't allow a size less than 128MB to be configured.
MIN_ZRAM_WRITEBACK_SIZE_MB=128

MARGIN_SPECIAL_FILE="/sys/kernel/mm/chromeos-low_mem/margin"
MIN_FILELIST_SPECIAL_FILE="/proc/sys/vm/min_filelist_kbytes"
MIN_FILELSIT_DEFAULT_VALUE_KB=100000
EXTRA_FREE_SPECIAL_FILE="/proc/sys/vm/extra_free_kbytes"
RAM_VS_SWAP_WEIGHT_SPECIAL_FILE="/sys/kernel/mm/chromeos-low_mem/ram_vs_swap_weight"

HIST_MIN=100
HIST_MAX=10000
HIST_BUCKETS=50
HIST_ARGS="${HIST_MIN} ${HIST_MAX} ${HIST_BUCKETS}"
# Upstart sets JOB, but we're not always called by upstart,
# so set it here too.
JOB="swap"

get_mem_total() {
  # Extract second field of MemTotal entry in /proc/meminfo.
  # NOTE: this could be done with "read", "case", and a function
  # that sets ram=$2, for a savings of about 3ms on an Alex.
  local mem_total
  mem_total=$(awk '/MemTotal/ { print $2; }' /proc/meminfo)
  if [ -z "${mem_total}" ]; then
    logger -t "${JOB}" "could not get MemTotal"
    exit 1
  fi
  echo "${mem_total}"
}

default_low_memory_margin() {
  # compute fraction of total RAM used for low-mem margin.  The fraction is
  # given in bips.  A "bip" or "basis point" is 1/100 of 1%.
  local critical_margin
  local moderate_margin
  CRITICAL_MARGIN_BIPS=520   # 5.2% FREE
  critical_margin=$(( $1 / 1024 * CRITICAL_MARGIN_BIPS / 10000 ))  # MiB
  MODERATE_MARGIN_BIPS=4000  # 40% FREE
  moderate_margin=$(( $1 / 1024 * MODERATE_MARGIN_BIPS / 10000 ))  # MiB
  echo "${critical_margin} ${moderate_margin}"
}

create_write_file() {
  file="$1"
  dir=$(dirname "${file}")
  content="$2"
  # Delete the file first in case its permissions have gotten ... weird.
  rm -f "${file}"
  mkdir -p -m 0755 "${dir}"
  echo "${content}" > "${file}"
}

# Log an error and exit.
die() {
  log_error "$*"
  exit 1
}

# Log a info level log message.
log_info() {
  logger -p daemon.info -t "${JOB}" -- "$*"
}

# Log a warning level log message.
log_warning() {
  logger -p daemon.warning -t "${JOB}" -- "$*"
}

# Log an error level log message.
log_error() {
  logger -p daemon.err -t "${JOB}" -- "$*"
}

start() {
  # Skip if zram swap is already on.
  if grep -q "zram0" /proc/swaps; then
    logger -t "${JOB}" "swap is already on"
    exit 0
  fi

  logger -t "${JOB}" "turning on swap"

  local mem_total low_mem_margin
  mem_total=$(get_mem_total)

  # Initialize the MM tunables
  low_mem_margin=$(default_low_memory_margin "${mem_total}")  # MiB
  echo "${low_mem_margin}" > "${MARGIN_SPECIAL_FILE}"
  echo "${MIN_FILELSIT_DEFAULT_VALUE_KB}" > "${MIN_FILELIST_SPECIAL_FILE}"

  # Allocate zram (compressed ram disk) for swap.
  # SWAP_ENABLE_FILE contains the zram size in MB.
  # Empty or missing SWAP_ENABLE_FILE means use default size.
  # 0 size means do not enable zram.
  # Calculations are in Kb to avoid 32 bit overflow.

  local requested_size_mb size_kb
  # For security, only read first few bytes of SWAP_ENABLE_FILE.
  requested_size_mb="$(head -c 5 "${SWAP_ENABLE_FILE}")" || :
  # If still empty, compute swap based on RAM size.
  if [ -z "${requested_size_mb}" ]; then
    # Default multiplier for zram size. (Shell math is integer only.)
    local multiplier="2"

    # The multiplier may be an expression, so it MUST use the $ expansion.
    size_kb=$(( mem_total * ${multiplier} ))
  elif [ "${requested_size_mb}" = "0" ]; then
    metrics_client Platform.CompressedSwapSize 0 ${HIST_ARGS}
    exit 0
  else
    size_kb=$(( requested_size_mb * 1024 ))
  fi

  # Load zram module.  Ignore failure (it could be compiled in the kernel).
  modprobe zram || logger -t "${JOB}" "modprobe zram failed (compiled?)"

  logger -t "${JOB}" "setting zram size to ${size_kb} Kb"
  # Approximate the kilobyte to byte conversion to avoid issues
  # with 32-bit signed integer overflow.
  echo "${size_kb}000" >/sys/block/zram0/disksize ||
  logger -t "${JOB}" "failed to set zram size"

  mkswap /dev/zram0 || logger -t "${JOB}" "mkswap /dev/zram0 failed"
  # Swapon may fail because of races with other programs that inspect all
  # block devices, so try several times.
  local tries=0
  while [ "${tries}" -le 10 ]; do
    swapon /dev/zram0 && break
    : $(( tries += 1 ))
    logger -t "${JOB}" "swapon /dev/zram0 failed, try ${tries}"
    sleep 0.1
  done

  local swaptotalkb
  swaptotalkb=$(awk '/SwapTotal/ { print $2 }' /proc/meminfo)
  metrics_client Platform.CompressedSwapSize \
                $(( swaptotalkb / 1024 )) ${HIST_ARGS}
}

stop() {
  # Skip if zram swap is already off.
  if ! grep -q "zram0" /proc/swaps; then
    logger -t "${JOB}" "swap is already off"
    exit 0
  fi

  logger -t "${JOB}" "turning off swap"

  # Fixup for mount namespace issue, b/248317295
  # Skip first line for header.
  tail -n +2 /proc/swaps | while read -r line; do
    # It is possible that the Filename of swap file zram0 in /proc/swaps shows
    # wrong path "/zram0", since devtmpfs in minijail mount namespace is lazily
    # unmounted while swap_management terminates.
    # If "/zram[0-9]" is found in /proc/swaps, add "/dev/" prefix for it.
    SWAP_PATH=$(echo "${line}" | awk '{print $1}' | sed -E 's/(^\/zram[0-9]+$)/\/dev\1/g')
    swapoff -v "${SWAP_PATH}"
  done

  if [ -b "/dev/zram0" ]; then
    # When we start up, we try to configure zram0, but it doesn't like to
    # be reconfigured on the fly.  Reset it so we can changes its params.
    # If there was a backing device being used, it will be automatically
    # removed because after it's created it was removed with deferred remove.
    echo 1 > /sys/block/zram0/reset || :
  fi
}

status() {
  # Show general swap info first.
  cat /proc/swaps

  # Show tunables.
  printf "low-memory margin (MiB): "
  cat "${MARGIN_SPECIAL_FILE}"
  printf "min_filelist_kbytes (KiB): "
  cat "${MIN_FILELIST_SPECIAL_FILE}"
  printf "ram_vs_swap_weight: "
  cat "${RAM_VS_SWAP_WEIGHT_SPECIAL_FILE}"
  if [ -e "${EXTRA_FREE_SPECIAL_FILE}" ]; then
    printf "extra_free_kbytes (KiB): "
    cat "${EXTRA_FREE_SPECIAL_FILE}"
  fi

  if [ -b "/dev/zram0" ]; then
    # Then spam various zram settings.
    local dir="/sys/block/zram0"
    printf '\ntop-level entries in %s:\n' "${dir}"
    cd "${dir}"
    grep -s '^' * || :
  fi
}

enable() {
  local size="$1"

  # Sizes of 0 or -1 mean restore factory default.
  # Don't confuse this with setting 0 in the file in the disable code path.
  if [ "${size}" = "0" -o  "${size}" = "-1" ]; then
    size=""
    logger -t "${JOB}" "enabling swap with default size"
  elif [ "${size}" -lt 100 -o "${size}" -gt 20000 ]; then
    echo "${JOB}: error: size ${size} is not between 100 and 20000" >&2
    exit 1
  else
    logger -t "${JOB}" "enabling swap via config with size ${size}"
  fi

  create_write_file "${SWAP_ENABLE_FILE}" "${size}"
}

disable() {
  logger -t "${JOB}" "disabling swap via config"
  create_write_file "${SWAP_ENABLE_FILE}" "0"
}

# Round up multiple will round the first argument (number) up to the next
# multiple of the second argument (alignment).
roundup_multiple() {
  local number=$1
  local alignment=$2
  echo $(( ( ( number + (alignment - 1) ) / alignment ) * alignment ))
}

INTEGRITY_LOOP_DEV=""
DATA_LOOP_DEV=""
# If we're unable to setup writeback just make sure we clean up any
# mounts or devices which may have been left.
cleanup_writeback_and_die() {
  # During cleanup we want to allow failures as we're unsure of the state
  # of the system we want the chance to clean everything up.
  set +e

  # If there is an error we want to make sure we cleanup.
  /sbin/dmsetup remove --deferred "${ZRAM_WRITEBACK_NAME}" 2>/dev/null
  /sbin/dmsetup remove --deferred "${ZRAM_INTEGRITY_NAME}" 2>/dev/null

  if [ -n "${INTEGRITY_LOOP_DEV}" ]; then
    losetup -d "${INTEGRITY_LOOP_DEV}" 2>/dev/null
  fi
  if [ -n "${DATA_LOOP_DEV}" ]; then
    losetup -d "${DATA_LOOP_DEV}" 2>/dev/null
  fi

  umount "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" 2>/dev/null
  rm -rf "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" 2>/dev/null

  # echo it to stderr (this is for debugd).
  echo "$*" >&2

  die "$*"
}

# Wait for up to 5 seconds for a dm device to become available,
# if it doesn't then die. This is needed because dm devices may take a
# few seconds to become visible at /dev/mapper after the table is switched.
wait_for_dm_device_or_die() {
  local device=$1
  local timeout=5
  local path="/dev/mapper/${device}"
  for _ in $(seq 1 "${timeout}"); do
    if [ -e "${path}" ]; then
      return
    fi
    sleep 1
  done
  cleanup_writeback_and_die "Device ${path} was not available in ${timeout} sec"
}

# Enable zram writeback with a given |size| specified in MB.
enable_zram_writeback() {
  local writeback_size_mb
  writeback_size_mb="$1"

  if [ -z "${writeback_size_mb}" ]; then
    die "zram writeback requires a size param"
  elif [ "${writeback_size_mb}" -lt 0 ]; then
    log_info "enabling zram writeback with default size ${DEFAULT_WRITEBACK_SIZE_MB}MB"
    writeback_size_mb=${DEFAULT_WRITEBACK_SIZE_MB}
  fi

  if [ ! -e "${ZRAM_BACKING_DEV}" ]; then
    die "missing ${ZRAM_BACKING_DEV}"
  elif [ "$(cat "${ZRAM_BACKING_DEV}")" != "none" ]; then
    die "zram already has a backing device assigned"
  elif [ -e "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" ]; then
    mountpoint -q "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" && die "zram writeback integrity ramfs is mounted"
    rm -rf "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" 2>/dev/null || die "unable to rm dir ${ZRAM_WRITEBACK_INTEGRITY_MOUNT}"
  fi

  local total_blocks free_blocks block_size pct_free
  # shellcheck disable=2046
  set -- $(stat -fc "%b %f %s" "${STATEFUL_PARTITION_DIR}")
  total_blocks="$1"
  free_blocks="$2"
  block_size="$3"
  pct_free=$(( 100 * free_blocks / total_blocks ))

  if [ "${pct_free}" -lt "${MIN_FREE_DISKSPACE_PCT}" ]; then
    die "zram writeback cannot be enabled free disk space" \
        "${pct_free}% is less than the minimum ${MIN_FREE_DISKSPACE_PCT}%"
  fi

  if [ "${writeback_size_mb}" -lt "${MIN_ZRAM_WRITEBACK_SIZE_MB}" ] ||
       [ "${writeback_size_mb}" -gt "${MAX_ZRAM_WRITEBACK_SIZE_MB}" ]; then
    die "zram writeback size ${writeback_size_mb}MB is not between" \
        "${MIN_ZRAM_WRITEBACK_SIZE_MB} and ${MAX_ZRAM_WRITEBACK_SIZE_MB}"
  fi

  # Now we need to make sure that the size we're using is never more than
  # MAX_PCT_OF_FREE_DISKSPACE. This is the percent of the FREE diskspace.
  local blocks_to_use pct_of_free writeback_size_bytes
  blocks_to_use=$(( ( writeback_size_mb * MB ) / block_size ))
  pct_of_free=$(( ( blocks_to_use * 100 ) / free_blocks ))

  if [ "${pct_of_free}" -gt "${MAX_PCT_OF_FREE_DISKSPACE}" ]; then
    local old_size="${writeback_size_mb}"
    blocks_to_use=$(( MAX_PCT_OF_FREE_DISKSPACE * ( free_blocks / 100 ) ))
    writeback_size_mb=$(( ( blocks_to_use * block_size ) / MB ))
    log_warning "zram writeback, requested size of ${old_size}MB" \
         "is ${pct_of_free}% of the free disk space. Size will be reduced to ${writeback_size_mb}MB"
  fi
  writeback_size_bytes=$(roundup_multiple $((writeback_size_mb * MB)) "${block_size}")

  # Because we rounded up writeback_size bytes recalculate the number of blocks used.
  blocks_to_use=$((writeback_size_bytes / block_size))

  # Create the actual writeback space on the stateful partition.
  local data_filename table
  data_filename=$(mktemp -p "${STATEFUL_PARTITION_DIR}" -t "zram_writeback.XXXXXX.swp")
  fallocate -l "${writeback_size_bytes}" "${data_filename}" ||
       cleanup_writeback_and_die "unable to fallocate writeback file"

  # See drivers/block/loop.c:230
  #  We support direct I/O only if lo_offset is aligned with the
  #  logical I/O size of backing device, and the logical block
  #  size of loop is bigger than the backing device's and the loop
  #  needn't transform transfer.
  DATA_LOOP_DEV=$(losetup --show --direct-io=on --sector-size="${block_size}" -f "${data_filename}")
  if [ -z "${DATA_LOOP_DEV}" ]; then
    cleanup_writeback_and_die "zram writeback unable to setup loop device"
  fi
  rm "${data_filename}" || cleanup_writeback_and_die "error: unable to unlink zram writeback file"

  # Create a dm-integrity device to use with dm-crypt.
  local integrity_table ramfs_size_bytes
  # AES-GCM uses a fixed 12 byte IV. The other 12 bytes are auth tag.
  local integrity_bytes_per_block=24
  # Eight 512 byte sectors are required for the superblock and eight padding sectors.
  local initial_size=$((16*512))
  ramfs_size_bytes=$(roundup_multiple $(( blocks_to_use * integrity_bytes_per_block + initial_size)) "${MB}")

  # shellcheck disable=2174
  mkdir -p "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" -m 0700 || cleanup_writeback_and_die "cannot create integrity mount"
  mount -t ramfs -n \
      -o size="${ramfs_size_bytes},noexec,nosuid,noatime,mode=0700" \
      "zram-writeback-integrity" "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" \
        || cleanup_writeback_and_die "unable to mount ramfs"
  integrity_filename=$(mktemp -p "${ZRAM_WRITEBACK_INTEGRITY_MOUNT}" -t "${LOOP_BLOCK_OPEN_PREFIX}zram_writeback.integrity.XXXXXX.swp")
  dd if=/dev/zero of="${integrity_filename}" iflag=count_bytes count="${ramfs_size_bytes}" status=none \
    || cleanup_writeback_and_die "unable to zero integrity file"

  INTEGRITY_LOOP_DEV=$(losetup --show -f "${integrity_filename}")
  if [ -z "${INTEGRITY_LOOP_DEV}" ]; then
    cleanup_writeback_and_die "ram writeback unable to setup integrity loop device"
  fi
  rm "${integrity_filename}" || cleanup_writeback_and_die "unable to unlink zram writeback integrity file"

  integrity_table="0 $(blockdev --getsz "${DATA_LOOP_DEV}") integrity \
      ${DATA_LOOP_DEV} 0 ${integrity_bytes_per_block} \
      D 2 block_size:${block_size} meta_device:${INTEGRITY_LOOP_DEV}"
  /sbin/dmsetup create "${ZRAM_INTEGRITY_NAME}" --table "${integrity_table}" ||
      cleanup_writeback_and_die "/sbin/dmsetup unable to create zram integrity device"
  wait_for_dm_device_or_die "${ZRAM_INTEGRITY_NAME}"

  # Both loop devices have been taken by the dm-integrity device, let's close them.
  losetup -d "${DATA_LOOP_DEV}" || cleanup_writeback_and_die "Unable to remove loop"
  losetup -d "${INTEGRITY_LOOP_DEV}" || cleanup_writeback_and_die "Unable to remove loop"

  # We can now clear these as they don't need to be cleaned up.
  DATA_LOOP_DEV=""
  INTEGRITY_LOOP_DEV=""

  table="0 $(blockdev --getsz "${ZRAM_INTEGRITY_DEV}") crypt capi:gcm(aes)-random \
      $(openssl rand -hex 32) \
      0 ${ZRAM_INTEGRITY_DEV} 0 4 allow_discards submit_from_crypt_cpus \
      sector_size:${block_size} integrity:${integrity_bytes_per_block}:aead"
  /sbin/dmsetup create "${ZRAM_WRITEBACK_NAME}" --table "${table}" ||
    cleanup_writeback_and_die "/sbin/dmsetup create ${ZRAM_WRITEBACK_NAME} failed"
  wait_for_dm_device_or_die "${ZRAM_WRITEBACK_NAME}"

  echo "${ZRAM_WRITEBACK_DEV_ENC}" > "${ZRAM_BACKING_DEV}" ||
    cleanup_writeback_and_die "unable to enable zram writeback with ${ZRAM_WRITEBACK_DEV_ENC}"

  # Now that the dm-crypt device has been opened by zram we can issue
  # a deferred remove which will cause it to be automatically removed
  # when it's closed.
  /sbin/dmsetup remove --deferred "${ZRAM_WRITEBACK_NAME}"
  /sbin/dmsetup remove --deferred "${ZRAM_INTEGRITY_NAME}"

  log_info "Enabled swap zram writeback with size ${writeback_size_mb}MB"

  # Make sure debugd can forward a success message.
  echo "Enabled writeback with size ${writeback_size_mb}MB"
}

usage() {
  cat <<EOF
Usage: $0  command <params>

       Available Commands:
           start
           stop
           status
           enable <size>
           disable
           enable_zram_writeback <size_mb>

Start or stop the use of the compressed swap file and get memory manager
tunable values.

The start phase is normally invoked by init during boot, but we never run the
stop phase when shutting down (since there's no point).  The stop phase is used
by developers via debugd to restart things on the fly.

Disabling changes the config, but doesn't actually turn on/off swap.
That will happen at the next reboot.

EOF
  exit $1
}

main() {
  set -e

  if [ $# -lt 1 ]; then
    usage 1
  fi

  # Make sure that the subcommand is one we know and that it has the right
  # number of arguments.
  local cmd="$1"
  shift
  case "${cmd}" in
  start|stop|status|disable)
    if [ $# -ne 0 ]; then
      usage 1
    fi
    ;;
  enable|enable_zram_writeback)
    if [ $# -ne 1 ]; then
      usage 1
    fi
    ;;
  *)
    usage 1
    ;;
  esac

  # Just call the func requested directly.
  ${cmd} "$@"
}
main "$@"
