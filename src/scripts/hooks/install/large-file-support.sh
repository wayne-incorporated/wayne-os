#!/bin/bash
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Detect 32bit builds that are using legacy 32bit file interfaces.
# https://en.wikipedia.org/wiki/Large_file_support

# Set ebuild vars to make shellcheck happy.
: "${ARCH:=}"
: "${CATEGORY:=}"
: "${D:=/}"
: "${PN:=}"
: "${PV:=}"
: "${RESTRICT:=}"
: "${WORKDIR:=}"

DOC_URL="https://issuetracker.google.com/201531268"

# Lists gleaned from headers and this doc:
# http://people.redhat.com/berrange/notes/largefile.html
# http://opengroup.org/platform/lfs.html
SYMBOLS=(
  # aio.h
  aio_cancel
  aio_error
  aio_fsync
  aio_read
  aio_return
  aio_suspend
  aio_write
  lio_listio

  # dirent.h
  alphasort
  getdirentries
  readdir
  readdir_r
  scandir
  scandirat
  versionsort

  # fcntl.h
  creat
  fallocate
  fopen
  fopenat
  freopen
  open
  openat
  posix_fadvise
  posix_fallocate
  __open
  __open_2
  __openat_2

  # ftw.h
  ftw
  nftw

  # glob.h
  glob
  globfree

  # stdio.h
  fgetpos
  fopen
  freopen
  fseeko
  fsetpos
  ftello
  tmpfile

  # stdlib.h
  mkostemp
  mkostemps
  mkstemp
  mkstemps

  # sys/mman.h
  mmap

  # sys/resource.h
  getrlimit
  prlimit
  setrlimit

  # sys/sendfile.h
  sendfile

  # sys/stat.h
  fstat
  fstatat
  lstat
  stat
  __fxstat
  __fxstatat
  __lxstat
  __xstat

  # sys/statfs.h
  fstatfs

  # sys/statvfs.h
  statvfs
  fstatvfs

  # unistd.h
  lockf
  lseek
  ftruncate
  pread
  preadv
  pwrite
  pwritev
  truncate
  __pread_chk
)
SYMBOLS_REGEX=$(printf '%s|' "${SYMBOLS[@]}")
SYMBOLS_REGEX="^(${SYMBOLS_REGEX%|})$"

# These are packages that are known to DTRT.  This list should only be updated
# with explicit review & documentation.
known_good_pkg() {
  case "${CATEGORY}/${PN}" in

  # All of the binaries provided by v4l-utils are built with LFS flags enabled,
  # except libv4l2tracer.so. This library wraps the interfaces for open, open64,
  # mmap, and mmap64 for tracing purposes which means they're only called when
  # the tracee program is not built with LFS.
  media-tv/v4l-utils) ;;

  # Provides wrappers to every C library interface, both LFS & non-LFS.
  # Internally it handles LFS correctly.  Its non-LFS references are only via
  # packages that are themselves broken.
  sys-apps/sandbox) ;;

  # https://bugs.gentoo.org/893656
  # zlib is quite intelligent when it comes to the standard LFS flags. z_off_t
  # is the only exported interface that uses off_t. In gzlib.c, a few APIs
  # (e.g. gzseek) are defined in terms of z_off_t, so with a 32-bit ABI that
  # splits values (e.g. arm 32-bit). This means the stack usage & return value
  # are ABI incompatible.
  #
  # Annoyingly, the only thing tripping up the checker is the call to open() in
  # gzlib.c, and zlib actually DTRT by using O_LARGEFILE when available.
  # Unfortunately, it's impossible from a symbol analysis point of view to
  # determine that. We would really need something that decompiles & analyzes
  # the opcodes to detect that this particular usage is correct.
  sys-libs/zlib) ;;

  *) return 1;;
  esac

  return 0
}

known_bad_pkg() {
  # Only allow this on arm as we have devices shipping that now.
  case "${ARCH}" in
  arm) ;;
  *) return 1;;
  esac

  # TODO(b/260698283): Ignore ARC (bionic) packages for now.
  case "${CATEGORY}/${PN}:${PV}" in
  media-libs/arc-cros-gralloc:*|\
  media-libs/arc-img-ddk:*|\
  media-libs/arc-mali-drivers:*|\
  media-libs/arc-mali-drivers-bifrost:*|\
  media-libs/arc-mali-drivers-bifrost-bin:*|\
  media-libs/arc-mali-drivers-valhall:*|\
  media-libs/arc-mali-drivers-valhall-bin:*|\
  media-libs/arc-mesa-freedreno:*|\
  media-libs/arc-mesa-img:*|\
  media-libs/arc-mesa-virgl:*|\
  media-libs/arcvm-mesa-freedreno:*|\
  x11-libs/arc-libdrm:*)
    return 0
    ;;
  esac

  # TODO(b/258669199): Ignore Rust packages for now.
  case "${CATEGORY}/${PN}:${PV}" in
  chromeos-base/crosvm:*|\
  chromeos-base/chunnel:*|\
  dev-rust/s9:*|\
  chromeos-base/factory_fai:*|\
  chromeos-base/ippusb_bridge:*|\
  chromeos-base/hwsec-utils:*|\
  chromeos-base/resourced:*|\
  media-gfx/deqp-runner:*|\
  media-sound/adhd:*|\
  media-sound/audio_processor:*|\
  media-sound/audio_streams_conformance_test:*|\
  media-sound/cras-client:*|\
  media-sound/cras_rust:*|\
  media-sound/cras_tests:*|\
  sys-apps/kexec-lite:*|\
  sys-firmware/sunplus-fwverify:*)
    return 0
    ;;
  esac

  # Packages in upstream discussion.  Must link to an upstream tracker.
  case "${CATEGORY}/${PN}:${PV}" in
  # https://bugs.gentoo.org/904190
  dev-libs/expat:2.5*) return 0;;
  # https://github.com/alsa-project/alsa-lib/pull/333
  media-libs/alsa-lib:*) return 0;;
  # https://github.com/alsa-project/alsa-utils/pull/223
  media-sound/alsa-utils:*) return 0;;
  esac

  # Do not add more packages here!
  case "${CATEGORY}/${PN}:${PV}" in
  app-accessibility/brltty:6.3|\
  app-admin/sysstat:11.7.4|\
  app-benchmarks/blktests:20190430|\
  app-benchmarks/blogbench:1.1.20200218|\
  app-benchmarks/bootchart:0.9.2|\
  app-benchmarks/pjdfstest:20190822|\
  app-crypt/nss:3.68.2|\
  app-crypt/tpm-tools:1.3.9.1|\
  app-crypt/trousers:0.3.3|\
  app-editors/qemacs:0.4.1_pre20170225|\
  app-editors/vim-core:9.0.*|\
  app-emulation/lx[cd]:3.*|\
  app-emulation/lx[cd]:4.0.*|\
  app-misc/ckermit:9.0.302|\
  app-misc/edid-decode:20210514|\
  app-misc/evtest:1.35|\
  app-misc/figlet:2.2.5|\
  app-misc/jq:1.4|\
  app-misc/screen:4.9.0|\
  app-misc/tmux:3.3a|\
  app-misc/utouch-evemu:1.0.5|\
  app-mobilephone/dfu-util:0.9|\
  app-shells/dash:0.5.9.1|\
  app-text/ghostscript-gpl:9.55.0|\
  app-text/htmltidy:20090325|\
  app-text/libpaper:1.1.28|\
  app-text/poppler:22.03.0|\
  chromeos-base/arc-key"ma"ster:0.0.1|\
  chromeos-base/audiotest:0.0.1|\
  chromeos-base/autotest-deps:0.0.4|\
  chromeos-base/autotest-deps-cellular:0.0.1|\
  chromeos-base/autotest-tests:0.0.4|\
  chromeos-base/autotest-tests-graphics:0.0.1|\
  chromeos-base/chromeos-chrome:*|\
  chromeos-base/chromeos-cr50-dev:0.0.1|\
  chromeos-base/crash-reporter:0.0.1|\
  chromeos-base/cronista:0.24.52|\
  chromeos-base/cros-camera:0.0.1|\
  chromeos-base/cros-camera-libs:0.0.1|\
  chromeos-base/croscomp:0.1.0|\
  chromeos-base/crosh:0.24.52|\
  chromeos-base/crostini_client:0.1.0|\
  chromeos-base/ec-utils:0.0.2|\
  chromeos-base/ec-utils-test:0.0.1|\
  chromeos-base/factory:0.2.0|\
  chromeos-base/factory_installer:0.0.1|\
  chromeos-base/g2update_tool:1.2.4905|\
  chromeos-base/gdix_hid_firmware_update:1.7.6|\
  chromeos-base/glbench:0.0.1|\
  chromeos-base/google-breakpad:2022.*|\
  chromeos-base/google-breakpad:2023.0[12]*|\
  chromeos-base/hps-firmware-tools:0.0.1|\
  chromeos-base/infineon-firmware-updater:1.1.2459.0|\
  chromeos-base/libevdev:0.0.1|\
  chromeos-base/libhwsec:0.0.1|\
  chromeos-base/manatee-runtime:0.1.0|\
  chromeos-base/memd:0.1.0|\
  chromeos-base/mttools:0.0.1|\
  chromeos-base/perfetto:29.0|\
  chromeos-base/perfetto_simple_producer:0.0.1|\
  chromeos-base/pixart_tpfwup:0.0.3|\
  chromeos-base/pixart_tpfwup:0.0.6|\
  chromeos-base/sirenia:0.24.52|\
  chromeos-base/sommelier:0.0.1|\
  chromeos-base/tast-local-helpers-cros:0.0.1|\
  chromeos-base/telemetry:0.0.1|\
  chromeos-base/tensorflow-internal:2.8.0|\
  chromeos-base/termina_container_tools:0.0.1|\
  chromeos-base/toolchain-tests:0.0.1|\
  chromeos-base/tpm2-simulator:0.0.1|\
  chromeos-base/tremplin:0.0.1|\
  chromeos-base/vkbench:0.0.1|\
  chromeos-base/vpd:0.0.1|\
  chromeos-base/wacom_fw_flash:1.4.0|\
  chromeos-base/weida_wdt_util:0.9.9|\
  dev-cpp/abseil-cpp:20211102.0|\
  dev-embedded/dfu-programmer:0.7.2|\
  dev-lang/tcl:8.6.12|\
  dev-libs/boost:1.79.0|\
  dev-libs/confuse:2.7|\
  dev-libs/flatbuffers:2.0.0|\
  dev-libs/fribidi:1.0.9|\
  dev-libs/iniparser:3.1|\
  dev-libs/json-c:0.14|\
  dev-libs/leveldb:1.23|\
  dev-libs/libconfig:1.5|\
  dev-libs/libcroco:0.6.12|\
  dev-libs/libev:4.33|\
  dev-libs/libfastjson:0.99.8|\
  dev-libs/libffi:3.1|\
  dev-libs/libfmt:7.1.3|\
  dev-libs/libgcrypt:1.8.8|\
  dev-libs/libgpg-error:1.36|\
  dev-libs/libgpiod:1.4.1|\
  dev-libs/libltdl:2.4.6|\
  dev-libs/libnl:1.1|\
  dev-libs/libnl:3.4.0|\
  dev-libs/libpcre2:10.34|\
  dev-libs/libpcre:8.44|\
  dev-libs/libunistring:0.9.10|\
  dev-libs/libusb:1.0.26|\
  dev-libs/libverto:0.3.0|\
  dev-libs/libxslt:1.1.35|\
  dev-libs/nettle:3.7.3|\
  dev-libs/nspr:4.32|\
  dev-libs/nss:3.68.2|\
  dev-libs/opensc:0.21.0|\
  dev-libs/openssl:1.1.1n|\
  dev-libs/protobuf:3.19.3|\
  dev-libs/tinyxml2:8.0.0|\
  dev-python/grpcio:1.43.*|\
  dev-python/numpy:1.19.4|\
  dev-python/python-uinput:0.11.2|\
  dev-python/selenium:3.0.2|\
  dev-rust/bindgen:0.59.2|\
  dev-util/android-tools:9.0.0_p3|\
  dev-util/apitrace:9.0|\
  dev-util/hdctools:0.0.1|\
  dev-rust/manatee-client:0.24.52|\
  dev-util/perf:5.15*|\
  dev-util/rt-tests:2.2|\
  dev-util/xdelta:3.0.11|\
  dev-util/xxd:1.10|\
  games-util/joystick:1.4.2|\
  gnome-base/librsvg:2.40.21|\
  media-fonts/font-util:1.3.2|\
  media-gfx/deqp-runner:0.13.1|\
  media-gfx/qrencode:3.4.4|\
  media-gfx/"sa"ne-backends:1.1.1|\
  media-gfx/zbar:0.23.1|\
  media-libs/clvk:0.0.1|\
  media-libs/cros-camera-hal-qti:0.0.1|\
  media-libs/cros-camera-libfs:0.0.1|\
  media-libs/cros-camera-sw-privacy-switch-test:0.0.1|\
  media-libs/dlm:0.0.1|\
  media-libs/freeimage:3.15.3|\
  media-libs/freetype:2.12*|\
  media-libs/ladspa-sdk:1.13|\
  media-libs/lcms:2.12|\
  media-libs/libjpeg-turbo:2.1.1|\
  media-libs/libpng:1.6.37|\
  media-libs/libv4lplugins:0.0.1|\
  media-libs/libvorbis:1.3.7|\
  media-libs/libyuv-test:1774|\
  media-libs/mali-drivers:1.20|\
  media-libs/mali-drivers-bin:1.20*|\
  media-libs/mali-drivers-bifrost:32.0|\
  media-libs/mali-drivers-bifrost-bin:32.0*|\
  media-libs/mali-drivers-valhall:32.0|\
  media-libs/mali-drivers-valhall-bin:32.0*|\
  media-libs/mesa-img:21.3*|\
  media-libs/opencl-cts:0.0.1|\
  media-libs/opencv:4.5.5|\
  media-libs/qti-7c-camera-bins:20220401|\
  media-libs/rockchip-isp1-3a-libs-bin:2018.06.28|\
  media-libs/sbc:1.3|\
  media-libs/shaderc:2022.1|\
  media-libs/skia:106|\
  media-libs/tiff:4.3.0|\
  media-libs/waffle:1.6.0|\
  media-plugins/alsa-plugins:1.1.6|\
  media-sound/gsm:1.0.13|\
  media-sound/sound_card_init:*|\
  media-video/yavta:0.0.1|\
  net-analyzer/netcat:110.20180111|\
  net-analyzer/netdata:1.34.1|\
  net-analyzer/netperf:2.7.0|\
  net-analyzer/tcpdump:4.9.3|\
  net-analyzer/traceroute:2.1.0|\
  net-dialup/lrzsz:0.12.20|\
  net-dialup/minicom:2.7|\
  net-dialup/ppp:2.4.9|\
  net-dialup/xl2tpd:1.3.12|\
  net-dns/avahi:0.8|\
  net-dns/bind-tools:9.11.2_p1|\
  net-firewall/conntrack-tools:1.4.4|\
  net-firewall/ebtables:2.0.11|\
  net-libs/grpc:1.16.*|\
  net-libs/grpc:1.43.*|\
  net-libs/libiio:0.23|\
  net-libs/libnetfilter_conntrack:1.0.6|\
  net-libs/libnsl:1.2.0|\
  net-libs/libsoup:2.58.2|\
  net-libs/libtirpc:1.0.2|\
  net-libs/libvncserver:0.9.13|\
  net-libs/rpcsvc-proto:1.3.1|\
  net-misc/bridge-utils:1.6|\
  net-misc/chrony:4.2|\
  net-misc/diag:0.1_p20210329|\
  net-misc/htpdate:1.0.4|\
  net-misc/iperf:2.0.9|\
  net-misc/iperf:3.7|\
  net-misc/iputils:20171016_pre|\
  net-misc/pps-tools:0.0.20120407|\
  net-misc/radvd:2.17|\
  net-misc/rmtfs:0.3_p20210408|\
  net-misc/socat:1.7.3.2|\
  net-misc/sslh:1.18|\
  net-misc/uftp:4.10.1|\
  net-misc/usbip:4.19|\
  net-print/cups-filters:1.28.7|\
  net-print/dymo-cups-drivers:1.4.0|\
  net-print/epson-inkjet-printer-escpr:1.7.18|\
  net-print/hplip:3.21.8|\
  net-print/starcupsdrv:3.11.0|\
  net-proxy/tinyproxy:1.10.0|\
  net-vpn/openvpn:2.4.4|\
  net-vpn/strongswan:5.9.4|\
  net-vpn/wireguard-tools:1.0.20200319|\
  net-wireless/bluez:5.54|\
  net-wireless/crda:3.18|\
  net-wireless/floss:0.0.2|\
  net-wireless/hostapd:2.11_pre|\
  net-wireless/iw:5.19|\
  net-wireless/wireless-tools:30_pre9|\
  net-wireless/wpa_supplicant-cros:2.11_pre|\
  sci-geosciences/gpsd:3.17|\
  sci-libs/tensorflow:2.8.0|\
  sys-apps/coreboot-utils:0.0.1|\
  sys-apps/debianutils:4.4|\
  sys-apps/dmidecode:3.2|\
  sys-apps/dtc:1.6.0|\
  sys-apps/ethtool:4.13|\
  sys-apps/flashmap:0.3|\
  sys-apps/flashrom-tester:1.6.0|\
  sys-apps/groff:1.22.4|\
  sys-apps/haveged:1.9.14|\
  sys-apps/hdparm:9.63|\
  sys-apps/i2c-tools:4.0|\
  sys-apps/install-xattr:0.5|\
  sys-apps/iotools:1.5|\
  sys-apps/kbd:1.15.5|\
  sys-apps/keyutils:1.6.3|\
  sys-apps/less:590|\
  sys-apps/lshw:02.19.2b_p20210121|\
  sys-apps/memtester:4.2.2|\
  sys-apps/nvme-cli:1.6|\
  sys-apps/pv:1.6.20|\
  sys-apps/restorecon:2.7|\
  sys-apps/smartmontools:7.3|\
  sys-apps/toybox:0.8.6|\
  sys-apps/usbguard:20210927|\
  sys-apps/usbutils:014|\
  sys-auth/nss-mdns:0.13|\
  sys-auth/pam_pwdfile:0.99|\
  sys-cluster/libqb:0.17.2|\
  sys-devel/bc:1.07.1|\
  sys-devel/binutils:2.40*|\
  sys-devel/flex:2.6.4|\
  sys-devel/gdb:9.2.20200923|\
  sys-devel/llvm:12.0.1|\
  sys-devel/llvm-img:9.0.0|\
  sys-fs/btrfs-progs:5.4.1|\
  sys-fs/e2fsprogs:1.47.0|\
  sys-fs/fuse:2.9.8|\
  sys-libs/gcc-libs:10.2.0|\
  sys-libs/libcap-ng:0.8.2|\
  sys-libs/libcxx:15.*|\
  sys-libs/libselinux:3.0|\
  sys-libs/libsepol:3.0|\
  sys-libs/mtdev:1.1.2|\
  sys-libs/pam:1.3.1|\
  sys-process/audit:3.0.6|\
  sys-process/htop:1.0.2|\
  sys-process/numactl:2.0.14|\
  sys-process/psmisc:23.3|\
  sys-process/time:1.9|\
  x11-base/xwayland:1.20.8|\
  x11-libs/pango:1.42.4)
    return 0
    ;;
  esac

  return 1
}

check_lfs()
{
  local files

  if known_good_pkg; then
    return
  fi

  # Exclude /build, since such files don't go into the final image.
  files="$(for d in "$@"; do \
           find "${d}" -path "${d}/build" -prune -o -type f -print0; done | \
           xargs -0 scanelf -F '%s %p' -qyRgs "-${SYMBOLS_REGEX}")"
  if [[ -n "${files}" ]]; then
    echo
    eqawarn "QA Notice: The following files were not built with LFS support:"
    eqawarn "  Please see ${DOC_URL} for details."
    eqawarn "${files}"
    eqawarn "Full build files:"
    scanelf -F '%s %F' -qyRgs "-${SYMBOLS_REGEX}" "${WORKDIR:-}"
    echo

    if ! known_bad_pkg; then
      die "package needs LFS support enabled -- see ${DOC_URL}"
    fi
  else
    if known_bad_pkg; then
      eqawarn "Please remove ${PN} exception from large-file-support.sh hook."
    fi
  fi
}

# Only check on 32-bit systems.  Filtering by $ARCH here isn't perfect, but it
# should be good enough for our needs so far.
case "${ARCH}" in
amd64|arm64|"")
  ;;
*)
  if [[ " ${RESTRICT} " != *" binchecks "* ]]; then
    check_lfs "${D}"
  fi
  ;;
esac

# Allow for people to run manually for testing/debugging.
if [[ $# -ne 0 ]]; then
  eqawarn() { echo " * $*"; }
  check_lfs "$@"
fi
