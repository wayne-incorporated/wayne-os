# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

CROS_WORKON_COMMIT=("e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd" "268f097da7b67a0943fddde3d30df2d366e825b7")
CROS_WORKON_TREE=("f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6" "5f52f55a4678653b15e0126bf489a8e105f32768" "7c95e8dbcaddb5b7cfd775817f029494fe9ee5a6")
CROS_WORKON_PROJECT=("chromiumos/platform2" "chromiumos/platform/camera")
CROS_WORKON_LOCALNAME=("../platform2" "../platform/camera")
CROS_WORKON_DESTDIR=("${S}/platform2" "${S}/platform2/platform_camera")
CROS_WORKON_SUBTREE=(".gn common-mk" "hal/mediatek")
CROS_WORKON_INCREMENTAL_BUILD="1"

PLATFORM_SUBDIR="platform_camera/hal/mediatek"

inherit cros-camera cros-workon platform

DESCRIPTION="Mediatek ISP Chrome OS camera HAL"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="-* arm arm64"

RDEPEND="
	chromeos-base/chromeos-config-tools
	chromeos-base/cros-camera-android-deps
	chromeos-base/cros-camera-libs
	media-libs/libsync
	media-libs/mtk-isp-3a-libs-bin
	media-libs/mtk-sensor-metadata
	media-libs/mtk-tuning-libs-bin"

DEPEND="${RDEPEND}
	media-libs/libyuv
	sys-kernel/linux-headers
	virtual/pkgconfig"

MTK_HAL_LIBRARIES=(
	"libcam.device3.so"
	"libcam.feature_utils.so"
	"libcam3_app.so"
	"libcam_algo.so"
	"libcam_algo_client.so"
	"libcam_iopie_common.so"
	"libcam_iopie_utils.so"
	"libcam_normalpipe.so"
	"libcam_normalstream.so"
	"libcamera.mt8183.so"
	"libcameracustom.so"
	"libfeature.face.so"
	"libfeature_3dnr.so"
	"libfeature_lmv.so"
	"libmtk_halsensor.so"
	"libmtk_mc_libv4l2.so"
	"libmtk_platform_log.so"
	"libmtk_property.so"
	"libmtkcam.featurepipe.capture.so"
	"libmtkcam.featurepipe.core.so"
	"libmtkcam.featurepipe.streaming.so"
	"libmtkcam.featurepipe.util.so"
	"libmtkcam.logicalmodule.so"
	"libmtkcam_3rdparty.so"
	"libmtkcam_debugutils.so"
	"libmtkcam_exif.so"
	"libmtkcam_fdvt.so"
	"libmtkcam_grallocutils.so"
	"libmtkcam_hwnode.so"
	"libmtkcam_hwutils.so"
	"libmtkcam_imgbuf.so"
	"libmtkcam_metadata.so"
	"libmtkcam_metastore.so"
	"libmtkcam_modulefactory_aaa.so"
	"libmtkcam_modulefactory_custom.so"
	"libmtkcam_modulefactory_drv.so"
	"libmtkcam_modulefactory_utils.so"
	"libmtkcam_modulehelper.so"
	"libmtkcam_pipeline.so"
	"libmtkcam_pipelinemodel.so"
	"libmtkcam_pipelinemodel_utils.so"
	"libmtkcam_pipelinepolicy.so"
	"libmtkcam_stdutils.so"
	"libmtkcam_streamutils.so"
	"libmtkcam_sysutils.so"
	"libmtkcam_tuning_utils.so"
	"libmtkcam_v4l2drvmgr.so"
)

src_install() {
	# install hal libs to dev
	for lib in "${MTK_HAL_LIBRARIES[@]}"; do
		dolib.so "${OUT}/lib/${lib}"
	done
	dobin "${OUT}"/setprop
	dobin "${OUT}"/getprop
	dobin "${OUT}"/eeprom_updater
	cros-camera_dohal "${OUT}/lib/libcamera.mt8183.so" mtk_cam_hal.so
}
