# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

DESCRIPTION="Firmware for tools based on Chromium OS EC"
HOMEPAGE="https://www.chromium.org/chromium-os/ec-development"

# stable channel firmware
C2D2_NAME="c2d2_v2.4.73-d771c18ba9"                # servo-firmware-R81-12768.40.0
SERVO_MICRO_NAME="servo_micro_v2.4.73-d771c18ba9"  # servo-firmware-R81-12768.71.0
SERVO_V4_NAME="servo_v4_v2.4.58-c37246f9c"         # servo-firmware-R81-12768.74.0
SERVO_V4P1_NAME="servo_v4p1_v2.0.20646-1fb66a343"  # EC ToT from 03/15/2023
SWEETBERRY_NAME="sweetberry_v2.3.7-096c7ee84"      # servo-firmware-R70-11011.14.0

# Prev channel firmware
C2D2_NAME_PREV="c2d2_v2.4.35-f1113c92b"                # servo-firmware-R81-12768.40.0
SERVO_MICRO_NAME_PREV="servo_micro_v2.4.57-ce329f64f"  # servo-firmware-R81-12768.40.0
SERVO_V4_NAME_PREV="servo_v4_v2.4.57-ce329f64f"        # servo-firmware-R81-12768.71.0
SERVO_V4P1_NAME_PREV="servo_v4p1_v2.0.8584+1a7e7e64c"  # servo fw used since april 2021

# Dev channel firmware
SERVO_V4P1_NAME_DEV="servo_v4p1_v2.0.18563-55348847f"  # EC ToT from 09/07/2022
C2D2_NAME_DEV="c2d2_v2.4.73-d771c18ba9"                # servo-firmware-R81-12768.151.0
SERVO_MICRO_NAME_DEV="servo_micro_v2.4.73-d771c18ba9"  # servo-firmware-R81-12768.151.0

# Alpha channel firmware
C2D2_NAME_ALPHA="c2d2_v2.0.18040-0fa6cb3063"                # R106-15042.0.0 build
SERVO_MICRO_NAME_ALPHA="servo_micro_v2.0.18040-0fa6cb3063"  # R106-15042.0.0 build
#channel is not needed for now, so stay with same version as stable to allow smooth transition in fleet
SERVO_V4P1_NAME_ALPHA="servo_v4p1_v2.0.20646-1fb66a343"  # EC ToT from 03/15/2023

UPDATER_PATH="/usr/share/servo_updater/firmware"

MIRROR_PATH="gs://chromeos-localmirror/distfiles/"

SRC_URI="
	${MIRROR_PATH}/${C2D2_NAME}.tar.xz
	${MIRROR_PATH}/${C2D2_NAME_DEV}.tar.xz
	${MIRROR_PATH}/${C2D2_NAME_PREV}.tar.gz
	${MIRROR_PATH}/${C2D2_NAME_ALPHA}.tar.xz
	${MIRROR_PATH}/${SERVO_MICRO_NAME}.tar.xz
	${MIRROR_PATH}/${SERVO_MICRO_NAME_DEV}.tar.xz
	${MIRROR_PATH}/${SERVO_MICRO_NAME_PREV}.tar.xz
	${MIRROR_PATH}/${SERVO_MICRO_NAME_ALPHA}.tar.xz
	${MIRROR_PATH}/${SERVO_V4_NAME}.tar.xz
	${MIRROR_PATH}/${SERVO_V4_NAME_PREV}.tar.xz
	${MIRROR_PATH}/${SERVO_V4P1_NAME}.tar.xz
	${MIRROR_PATH}/${SERVO_V4P1_NAME_PREV}.tar.xz
	${MIRROR_PATH}/${SERVO_V4P1_NAME_DEV}.tar.xz
	${MIRROR_PATH}/${SERVO_V4P1_NAME_ALPHA}.tar.xz
	${MIRROR_PATH}/${SWEETBERRY_NAME}.tar.gz
	"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

DEPEND=""
RDEPEND="!<chromeos-base/ec-devutils-0.0.2"

S="${WORKDIR}"

src_install() {
	insinto "${UPDATER_PATH}"

	doins "${C2D2_NAME}.bin"
	doins "${C2D2_NAME_DEV}.bin"
	doins "${C2D2_NAME_ALPHA}.bin"
	doins "${C2D2_NAME_PREV}.bin"
	dosym "${C2D2_NAME_ALPHA}.bin" "${UPDATER_PATH}/c2d2.alpha.bin"
	dosym "${C2D2_NAME}.bin" "${UPDATER_PATH}/c2d2.stable.bin"
	dosym "${C2D2_NAME_DEV}.bin" "${UPDATER_PATH}/c2d2.dev.bin"
	dosym "${C2D2_NAME_PREV}.bin" "${UPDATER_PATH}/c2d2.prev.bin"

	doins "${SERVO_MICRO_NAME}.bin"
	doins "${SERVO_MICRO_NAME_DEV}.bin"
	doins "${SERVO_MICRO_NAME_ALPHA}.bin"
	doins "${SERVO_MICRO_NAME_PREV}.bin"
	dosym "${SERVO_MICRO_NAME_ALPHA}.bin" "${UPDATER_PATH}/servo_micro.alpha.bin"
	dosym "${SERVO_MICRO_NAME}.bin" "${UPDATER_PATH}/servo_micro.stable.bin"
	dosym "${SERVO_MICRO_NAME_DEV}.bin" "${UPDATER_PATH}/servo_micro.dev.bin"
	dosym "${SERVO_MICRO_NAME_PREV}.bin" "${UPDATER_PATH}/servo_micro.prev.bin"

	doins "${SERVO_V4_NAME}.bin"
	doins "${SERVO_V4_NAME_PREV}.bin"
	dosym "${SERVO_V4_NAME}.bin" "${UPDATER_PATH}/servo_v4.alpha.bin"
	dosym "${SERVO_V4_NAME}.bin" "${UPDATER_PATH}/servo_v4.stable.bin"
	dosym "${SERVO_V4_NAME}.bin" "${UPDATER_PATH}/servo_v4.dev.bin"
	dosym "${SERVO_V4_NAME_PREV}.bin" "${UPDATER_PATH}/servo_v4.prev.bin"

	doins "${SERVO_V4P1_NAME}.bin"
	doins "${SERVO_V4P1_NAME_PREV}.bin"
	doins "${SERVO_V4P1_NAME_DEV}.bin"
	doins "${SERVO_V4P1_NAME_ALPHA}.bin"
	dosym "${SERVO_V4P1_NAME_ALPHA}.bin" "${UPDATER_PATH}/servo_v4p1.alpha.bin"
	dosym "${SERVO_V4P1_NAME}.bin" "${UPDATER_PATH}/servo_v4p1.stable.bin"
	dosym "${SERVO_V4P1_NAME_DEV}.bin" "${UPDATER_PATH}/servo_v4p1.dev.bin"
	dosym "${SERVO_V4P1_NAME_PREV}.bin" "${UPDATER_PATH}/servo_v4p1.prev.bin"

	doins "${SWEETBERRY_NAME}.bin"
	dosym "${SWEETBERRY_NAME}.bin" "${UPDATER_PATH}/sweetberry.alpha.bin"
	dosym "${SWEETBERRY_NAME}.bin" "${UPDATER_PATH}/sweetberry.stable.bin"
	dosym "${SWEETBERRY_NAME}.bin" "${UPDATER_PATH}/sweetberry.dev.bin"
}
