# Copyright 2009 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# This project checks out the proto files from the read only repositories
# linked to the following directories of the Chromium project:

#   - src/components/policy

# This project is not cros-work-able: if changes to the protobufs are needed
# then they should be done in the Chromium repository, and the commits below
# should be updated.

EAPI="7"

CROS_WORKON_PROJECT=(
	"chromium/src/components/policy"

	# private_membership and shell-encryption are not used in Chrome OS at
	# the moment. They are just required to compile the proto files. An
	# uprev will only be necessary if the respective proto files change.
	"chromium/src/third_party/private_membership"
	"chromium/src/third_party/shell-encryption"
)

CROS_WORKON_LOCALNAME=(
	"chromium/src/components/policy"
	"chromium/src/third_party/private_membership"
	"chromium/src/third_party/shell-encryption"
)

CROS_WORKON_DESTDIR=(
	"${S}/cloud/policy"
	"${S}/private_membership"
	"${S}/shell-encryption"
)

CROS_WORKON_EGIT_BRANCH=(
	"main"
	"main"
	"main"
)

CROS_WORKON_MANUAL_UPREV=1

PYTHON_COMPAT=( python3_{6..9} )

inherit cros-constants cros-workon eutils python-any-r1

DESCRIPTION="Protobuf installer for the device policy proto definitions."
HOMEPAGE="https://chromium.googlesource.com/chromium/src/components/policy"

LICENSE="BSD-Google"
SLOT="0/${PV}"
KEYWORDS="~*"
IUSE=""

POLICY_DIR="${S}/cloud/policy"

PRIVATE_MEMBERSHIP_DIR="${S}/private_membership/src"
SHELL_ENCRYPTION_DIR="${S}/shell-encryption/src"

# A list of the static protobuf files that exist in Chromium.
POLICY_DIR_PROTO_FILES=(
	"chrome_device_policy.proto"
	"chrome_extension_policy.proto"
	"device_management_backend.proto"
	"install_attributes.proto"
	"policy_common_definitions.proto"
	"policy_signing_key.proto"
	"secure_connect.proto"
)

RDEPEND="!<chromeos-base/chromeos-chrome-82.0.4056.0_rc-r1"

src_compile() {
	# Generate policy_templates.json
	"${POLICY_DIR}/resources/policy_templates.py" \
		--dest="${POLICY_DIR}/resources/generated_policy_templates.json" \
		|| die "Failed to generate policy_templates.json"

	# Generate cloud_policy.proto.
	"${POLICY_DIR}/tools/generate_policy_source.py" \
		--cloud-policy-protobuf="${WORKDIR}/cloud_policy.proto" \
		--chrome-version-file="${FILESDIR}/VERSION" \
		--policy-templates-file="${POLICY_DIR}/resources/generated_policy_templates.json" \
		--target-platform="chrome_os" \
		|| die "Failed to generate cloud_policy.proto"
}

src_install() {
	insinto /usr/include/proto
	doins "${POLICY_DIR}"/proto/chrome_device_policy.proto
	doins "${POLICY_DIR}"/proto/chrome_extension_policy.proto
	doins "${POLICY_DIR}"/proto/install_attributes.proto
	doins "${POLICY_DIR}"/proto/policy_signing_key.proto
	doins "${POLICY_DIR}"/proto/device_management_backend.proto
	doins "${POLICY_DIR}"/test_support/remote_commands_service.proto
	doins "${PRIVATE_MEMBERSHIP_DIR}"/private_membership_rlwe.proto
	doins "${PRIVATE_MEMBERSHIP_DIR}"/private_membership.proto
	doins "${SHELL_ENCRYPTION_DIR}"/serialization.proto
	insinto /usr/share/protofiles
	doins "${POLICY_DIR}"/proto/chrome_device_policy.proto
	doins "${POLICY_DIR}"/proto/policy_common_definitions.proto
	doins "${POLICY_DIR}"/proto/device_management_backend.proto
	doins "${POLICY_DIR}"/proto/chrome_extension_policy.proto
	doins "${POLICY_DIR}"/test_support/remote_commands_service.proto
	doins "${PRIVATE_MEMBERSHIP_DIR}"/private_membership_rlwe.proto
	doins "${PRIVATE_MEMBERSHIP_DIR}"/private_membership.proto
	doins "${SHELL_ENCRYPTION_DIR}"/serialization.proto
	doins "${WORKDIR}"/cloud_policy.proto
	insinto /usr/share/policy_resources
	doins "${POLICY_DIR}"/resources/generated_policy_templates.json
	doins "${FILESDIR}"/VERSION
	exeinto /usr/share/policy_tools
	doexe "${POLICY_DIR}"/tools/generate_policy_source.py

	# Retrieve the proto files which exist in that path, with their full paths.
	local policy_dir_proto_files=( "${POLICY_DIR}"/proto/*.proto )

	# Convert policy_dir_proto_files into an array, and retrieving the files names, instead of their full path.
	policy_dir_proto_files=( "${policy_dir_proto_files[@]##*/}" )

	# Check whether all protobuf files that exist in Chromium side has already been installed in protofiles package or
	# not. And to verify that the list in autotests package, which is using these protobuf files are up-to-date.
	sorter() {
		printf '%s\n' "$@" | LC_ALL=C sort
	}
	if [[ "$(sorter "${policy_dir_proto_files[@]}")" != "$(sorter "${POLICY_DIR_PROTO_FILES[@]}")" ]]; then
		die "Add all new protobuf files into the sorted list of chromium protobuf files, which exist in protofiles package.
			Please update all the imported protobuf files in autotest package in policy_protos.py file."
	fi
}
