# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="e687d49261f807d96ce5b9d8f1bfa8f184aa5bbd"
CROS_WORKON_TREE=("5f52f55a4678653b15e0126bf489a8e105f32768" "87ad1186bfc1f34a7c4b189f85791d0856febe36" "f91b6afd5f2ae04ee9a2c19109a3a4a36f7659e6")
CROS_GO_PACKAGES=(
	"chromiumos/system_api/..."
)

CROS_WORKON_LOCALNAME="platform2"
CROS_WORKON_PROJECT="chromiumos/platform2"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_SUBTREE="common-mk system_api .gn"

PLATFORM_SUBDIR="system_api"
WANT_LIBBRILLO="no"

inherit cros-fuzzer cros-go cros-workon platform

DESCRIPTION="Chrome OS system API (D-Bus service names, etc.)"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/HEAD/system_api/"
LICENSE="BSD-Google"
# The subslot should be manually bumped any time protobuf is upgraded
# to a newer version whose libraries are incompatible with the
# generated sources of the previous version. As a rule of thumb if the
# minor version of protobuf has changed, the subslot should be incremented.
SLOT="0/1"
KEYWORDS="*"
IUSE="cros_host"

RDEPEND="
	dev-libs/protobuf:=
	cros_host? ( net-libs/grpc:= )
"

DEPEND="${RDEPEND}
	dev-go/protobuf:=
	dev-go/protobuf-legacy-api:=
"

src_unpack() {
	platform_src_unpack
	CROS_GO_WORKSPACE="${OUT}/gen/go"
}

src_install() {
	platform_src_install

	insinto /usr/"$(get_libdir)"/pkgconfig
	doins system_api.pc

	insinto /usr/include/chromeos
	doins -r dbus switches constants mojo
	find "${D}" -name OWNERS -delete || die

	# Install the dbus-constants.h files in the respective daemons' client library
	# include directory. Users will need to include the corresponding client
	# library to access these files.
	local dir dirs=(
		anomaly_detector
		attestation
		biod
		chunneld
		cros-disks
		cros_healthd
		cryptohome
		debugd
		discod
		dlcservice
		kerberos
		login_manager
		lorgnette
		oobe_config
		runtime_probe
		pciguard
		permission_broker
		power_manager
		rgbkbd
		rmad
		shadercached
		shill
		smbprovider
		tpm_manager
		u2f
		update_engine
		wilco_dtc_supportd
	)
	for dir in "${dirs[@]}"; do
		insinto /usr/include/"${dir}"-client/"${dir}"
		doins dbus/"${dir}"/dbus-constants.h
	done

	# These are files/projects installed in the common dir.
	dirs=( system_api )

	# These are project-specific files.
	while IFS='' read -r dbus_project; do dirs+=("${dbus_project}"); done < <(
		cd "${S}/dbus" || die
		dirname -- */*.proto | sort -u
	)

	for dir in "${dirs[@]}"; do
		if [[ -d "${OUT}/gen/include/${dir}/proto_bindings" ]]; then
			insinto /usr/include/"${dir}"/proto_bindings
			doins "${OUT}"/gen/include/"${dir}"/proto_bindings/*.h
		else
			insinto /usr/include/"${dir}"
			doins "${OUT}"/gen/include/"${dir}"/*.h
		fi

		if [[ "${dir}" == "system_api" ]]; then
			dolib.a "${OUT}/libsystem_api-protos.a"
		else
			dolib.a "${OUT}/libsystem_api-${dir}-protos.a"
		fi
	done

	dolib.so "${OUT}/lib/libsystem_api.so"

	cros-go_src_install
}
