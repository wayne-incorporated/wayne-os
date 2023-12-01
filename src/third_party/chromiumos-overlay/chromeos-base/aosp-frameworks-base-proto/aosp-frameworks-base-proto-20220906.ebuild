# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

# Honor the imports from the proto files + our own prefix.
CROS_GO_PACKAGES=(
	"android.com/frameworks/..."
)

inherit cros-go

DESCRIPTION="AOSP frameworks/base protobuf files"
HOMEPAGE="https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android13-dev/core/proto/"
GIT_COMMIT="f564bb5b380f336bfe453718d8ddb7e7c51057dc"
GIT_COMMIT_PROTO_LOGGING="3b3844a3601b3f0f05d0403a32347101b9a562d9"
SRC_URI="https://android.googlesource.com/platform/frameworks/base/+archive/${GIT_COMMIT}/core/proto.tar.gz -> aosp-frameworks-base-core-proto-${PV}.tar.gz
		https://android.googlesource.com/platform/frameworks/proto_logging/+archive/${GIT_COMMIT_PROTO_LOGGING}/stats/enums.tar.gz -> aosp-frameworks-proto-logging-stats-enums-${PV}.tar.gz
		"
LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"

RDEPEND=""

DEPEND="${RDEPEND}
	dev-go/protobuf
	dev-go/protobuf-legacy-api
	dev-libs/protobuf:=
"

S=${WORKDIR}

src_unpack() {
	# Unpack the tar.gz files manually since they need to be unpacked in special directories.

	mkdir -p frameworks/base/core/proto || die
	mkdir -p frameworks/proto_logging/stats/enums || die

	pushd . || die
	cd frameworks/base/core/proto || die
	unpack "aosp-frameworks-base-core-proto-${PV}.tar.gz"
	popd || die

	pushd . || die
	cd frameworks/proto_logging/stats/enums || die
	unpack "aosp-frameworks-proto-logging-stats-enums-${PV}.tar.gz"
	popd || die
}

src_compile() {
	# SRC_URI contains all .proto files from Android frameworks/base (~160 .proto files).
	# For Tast, we only need a subset: Activity Manager,  Window Manager,
	# and its dependencies.
	# If there is a need to add more, add a new "protoc" or extend an
	# existing one.

	local core_path="frameworks/base/core/proto/android"
	local proto_logging_path="frameworks/proto_logging/stats/enums"
	# core/proto path
	local cp="${WORKDIR}/${core_path}"
	# proto_logging/stats/enums path
	local pse="${WORKDIR}/${proto_logging_path}"
	local out="${WORKDIR}/gen/go/src"

	# protoc allow us to map a "protobuf import" with a "golang import".
	# This is the list of protobuf import files that need to get remapped
	# to use the "android.com" prefix. Basically all the generated golang
	# files must use the "android.com" import prefix.
	local imports_to_remap=(
		"${core_path}/app/activitymanager.proto"
		"${core_path}/app/appexitinfo.proto"
		"${core_path}/app/notification.proto"
		"${core_path}/app/profilerinfo.proto"
		"${core_path}/app/statusbarmanager.proto"
		"${core_path}/app/window_configuration.proto"
		"${core_path}/content/activityinfo.proto"
		"${core_path}/content/component_name.proto"
		"${core_path}/content/configuration.proto"
		"${core_path}/content/intent.proto"
		"${core_path}/content/locale.proto"
		"${core_path}/content/package_item_info.proto"
		"${core_path}/graphics/pixelformat.proto"
		"${core_path}/graphics/point.proto"
		"${core_path}/graphics/rect.proto"
		"${core_path}/internal/processstats.proto"
		"${core_path}/os/bundle.proto"
		"${core_path}/os/looper.proto"
		"${core_path}/os/message.proto"
		"${core_path}/os/messagequeue.proto"
		"${core_path}/os/patternmatcher.proto"
		"${core_path}/os/powermanager.proto"
		"${core_path}/os/worksource.proto"
		"${core_path}/privacy.proto"
		"${core_path}/typedef.proto"
		"${core_path}/server/activitymanagerservice.proto"
		"${core_path}/server/animationadapter.proto"
		"${core_path}/server/intentresolver.proto"
		"${core_path}/server/surfaceanimator.proto"
		"${core_path}/server/windowcontainerthumbnail.proto"
		"${core_path}/server/windowmanagerservice.proto"
		"${core_path}/util/common.proto"
		"${core_path}/view/display.proto"
		"${core_path}/view/displaycutout.proto"
		"${core_path}/view/displayinfo.proto"
		"${core_path}/view/insetssource.proto"
		"${core_path}/view/insetssourcecontrol.proto"
		"${core_path}/view/remote_animation_target.proto"
		"${core_path}/view/surface.proto"
		"${core_path}/view/surfacecontrol.proto"
		"${core_path}/view/windowlayoutparams.proto"
		"${proto_logging_path}/app/enums.proto"
		"${proto_logging_path}/app/job/enums.proto"
		"${proto_logging_path}/bluetooth/enums.proto"
		"${proto_logging_path}/net/enums.proto"
		"${proto_logging_path}/os/enums.proto"
		"${proto_logging_path}/server/job/enums.proto"
		"${proto_logging_path}/service/enums.proto"
		"${proto_logging_path}/service/procstats_enum.proto"
		"${proto_logging_path}/telephony/enums.proto"
		"${proto_logging_path}/view/enums.proto"
	)

	# Specifies the go_package for each protobuf file. E.g. for file
	# frameworks/core/display.proto, use go_package
	# "android.com/frameworks/core".
	#
	# Write the go_package option just below the package option.
	for fp in "${imports_to_remap[@]}"; do
		sed -i "/^package [a-z.]*[a-z]\+;$/ a\
		option go_package = \"android.com/${fp%/*}\";" "${WORKDIR}/${fp}" || die
	done


	mkdir -p "${out}" || die

	# One "protoc" invocation per directory, otherwise it will create
	# package conflicts.
	# Use a different "import_path" per directory to avoid name conflict.
	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/privacy.proto" \
		"${cp}/typedef.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/app/activitymanager.proto" \
		"${cp}/app/appexitinfo.proto" \
		"${cp}/app/notification.proto" \
		"${cp}/app/profilerinfo.proto" \
		"${cp}/app/statusbarmanager.proto" \
		"${cp}/app/window_configuration.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/content/activityinfo.proto" \
		"${cp}/content/component_name.proto" \
		"${cp}/content/configuration.proto" \
		"${cp}/content/intent.proto" \
		"${cp}/content/locale.proto" \
		"${cp}/content/package_item_info.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/graphics/pixelformat.proto" \
		"${cp}/graphics/point.proto" \
		"${cp}/graphics/rect.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/internal/processstats.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/os/bundle.proto" \
		"${cp}/os/looper.proto" \
		"${cp}/os/message.proto" \
		"${cp}/os/messagequeue.proto" \
		"${cp}/os/patternmatcher.proto" \
		"${cp}/os/powermanager.proto" \
		"${cp}/os/worksource.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/server/activitymanagerservice.proto" \
		"${cp}/server/animationadapter.proto" \
		"${cp}/server/intentresolver.proto" \
		"${cp}/server/surfaceanimator.proto" \
		"${cp}/server/windowcontainerthumbnail.proto" \
		"${cp}/server/windowmanagerservice.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/util/common.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${cp}/view/display.proto" \
		"${cp}/view/displaycutout.proto" \
		"${cp}/view/displayinfo.proto" \
		"${cp}/view/insetssource.proto" \
		"${cp}/view/insetssourcecontrol.proto" \
		"${cp}/view/remote_animation_target.proto" \
		"${cp}/view/surface.proto" \
		"${cp}/view/surfacecontrol.proto" \
		"${cp}/view/windowlayoutparams.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/app/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/app/job/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/bluetooth/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/net/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/os/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/net/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/server/job/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/service/enums.proto" \
		"${pse}/service/procstats_enum.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/telephony/enums.proto" \
		|| die

	protoc \
		--go_out="${out}" \
		--proto_path="${WORKDIR}" \
		"${pse}/view/enums.proto" \
		|| die

	CROS_GO_WORKSPACE="${WORKDIR}/gen/go/"
}
