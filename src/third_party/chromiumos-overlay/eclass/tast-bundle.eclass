# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: tast-bundle.eclass
# @MAINTAINER:
# The ChromiumOS Authors <chromium-os-dev@chromium.org>
# @BUGREPORTS:
# Please report bugs via https://crbug.com/new (with component "Tests>Tast")
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for building and installing Tast test bundles.
# @DESCRIPTION:
# Installs Tast integration test bundles.
# See https://chromium.googlesource.com/chromiumos/platform/tast/ for details.
# The bundle name (e.g. "cros") and type ("local" or "remote") are derived from
# the package name, which should be of the form "tast-<type>-tests-<name>".

# @ECLASS-VARIABLE: TAST_BUNDLE_PRIVATE
# @DESCRIPTION:
# If set to "1", this test bundle is not installed to images, but is downloaded
# at run time by local_test_runner. Otherwise this test bundle is installed to
# images.
# Only local tests can be marked private; remote test bundles are always
# installed to the chroot.
: "${TAST_BUNDLE_PRIVATE:=0}"

# @ECLASS-VARIABLE: TAST_BUNDLE_EXCLUDE_DATA_FILES
# @DESCRIPTION:
# If set to "1", test data files are not copied.
# This must be set to 1 if the ebuild inherits tast-bundle-data.eclass
# and that eclass copies the data files instead.
: "${TAST_BUNDLE_EXCLUDE_DATA_FILES:=0}"

# @ECLASS-VARIABLE: TAST_BUNDLE_ROOT
# @DESCRIPTION:
# It is the root of the full path of the Tast bundle to be installed.
: "${TAST_BUNDLE_ROOT:="go.chromium.org/tast-tests/cros"}"

inherit cros-workon cros-go

DEPEND="dev-go/crypto"
RDEPEND="app-arch/tar"

if ! [[ "${PN}" =~ ^tast-(local|remote)-tests-[a-z]+$ ]]; then
	die "Package \"${PN}\" not of form \"tast-<type>-tests-<name>\""
fi

# @FUNCTION: tast-bundle_pkg_setup
# @DESCRIPTION:
# Parses package name to extract bundle info and sets binary target.
tast-bundle_pkg_setup() {
	# Strip off the "tast-" prefix and the "-tests-*" suffix to get the type
	# ("local" or "remote").
	local tmp=${PN#tast-}
	TAST_BUNDLE_TYPE=${tmp%-tests-*}

	# Strip off everything preceding the bundle name.
	TAST_BUNDLE_NAME=${PN#tast-*-tests-}

	# Decide if this is a private bundle.
	TAST_BUNDLE_PREFIX=/usr
	if [[ "${TAST_BUNDLE_PRIVATE}" = 1 ]]; then
		if [[ "${TAST_BUNDLE_TYPE}" == local ]]; then
			TAST_BUNDLE_PREFIX=/build
		fi
	fi

	# The path to the test bundle code relative to the src/ directory.
	TAST_BUNDLE_PATH="${TAST_BUNDLE_ROOT}/${TAST_BUNDLE_TYPE}/bundles/${TAST_BUNDLE_NAME}"

	# Install the bundle under /{usr|build}/libexec/tast/bundles/<type>.
	CROS_GO_BINARIES=(
		"${TAST_BUNDLE_ROOT}/${TAST_BUNDLE_TYPE}/bundles/${TAST_BUNDLE_NAME}:${TAST_BUNDLE_PREFIX}/libexec/tast/bundles/${TAST_BUNDLE_TYPE}/${TAST_BUNDLE_NAME}"
	)

	CROS_GO_VET_FLAGS=(
		# Check printf-style arguments passed to testing.State methods.
		"-printf.funcs=Log,Logf,Error,Errorf,Fatal,Fatalf,Wrap,Wrapf"
		# Check the result of a function without side effects is used.
		"-unusedresult.funcs=errors.New,errors.Wrap,errors.Wrapf,fmt.Errorf,fmt.Sprint,fmt.Sprintf,sort.Reverse"
	)
}

# @FUNCTION: tast-bundle_src_prepare
# @DESCRIPTION:
# Sets up environment variables for the Go toolchain.
tast-bundle_src_prepare() {
	# Disable cgo and PIE on building Tast binaries. See:
	# https://crbug.com/976196
	# https://github.com/golang/go/issues/30986#issuecomment-475626018
	export CGO_ENABLED=0
	export GOPIE=0
	# Workaround to unblock Go uprevs until ChromeOS packages are converted to modules
	export GO111MODULE=off

	default
}

# @FUNCTION: tast-bundle_src_compile
# @DESCRIPTION:
# Compiles test bundle executables and generate associated misc files.
tast-bundle_src_compile() {
	cros-go_src_compile

	local i
	for (( i = 0; i < ${#CROS_WORKON_PROJECT[@]}; i++ )); do
		echo "${CROS_WORKON_REPO[i]}/${CROS_WORKON_PROJECT[i]} ${CROS_WORKON_COMMIT[i]}"
	done | jq -s -R -S 'split("\n") |
		map(split(" ") | select(.[0]) | {(.[0]): .[1]}) |
		add' > "${TAST_BUNDLE_NAME}.sig.json" || die "Generating signatures failed"

	# Build bundle executable for the host arch and get metadata dump.
	local source="${TAST_BUNDLE_ROOT}/${TAST_BUNDLE_TYPE}/bundles/${TAST_BUNDLE_NAME}"
	local host_exec="host_${TAST_BUNDLE_NAME}"
	GO111MODULE=off GOPATH="$(cros-go_gopath)" go build -v \
		${CROS_GO_VERSION:+"-ldflags=-X main.Version=${CROS_GO_VERSION}"} \
		-o "${host_exec}" \
		"${source}" || die "Generating bundle for host"
	"./${host_exec}" -exportmetadata > "${TAST_BUNDLE_NAME}.pb" || die "Exporting test metadata"
}

# @FUNCTION: tast-bundle_src_test
# @DESCRIPTION:
# Runs unit tests.
tast-bundle_src_test() {
	# Some unit tests write to /proc/self/comm to test interaction with
	# external processes.
	addwrite /proc/self/comm

	cros-go_src_test
}

# @FUNCTION: tast-bundle_src_install
# @DESCRIPTION:
# Installs test bundle executables, associated data files and other misc files.
tast-bundle_src_install() {
	cros-go_src_install

	insinto "${TAST_BUNDLE_PREFIX}/share/tast/signature/${TAST_BUNDLE_TYPE}"
	newins "${TAST_BUNDLE_NAME}.sig.json" "${TAST_BUNDLE_NAME}.json"

	if [[ "${TAST_BUNDLE_EXCLUDE_DATA_FILES}" -ne 1 ]]; then
		# The base directory where test data files are installed.
		local basedatadir="${TAST_BUNDLE_PREFIX}/share/tast/data"

		# Install each test category's data dir.
		pushd src >/dev/null || die "failed to pushd src"
		local datadir dest
		for datadir in "${TAST_BUNDLE_PATH}"/*/data; do
			[[ -e "${datadir}" ]] || break

			# Dereference symlinks to support shared files: https://crbug.com/927424
			dest=${ED%/}/${basedatadir#/}/${datadir%/*}
			mkdir -p "${dest}" || die "Failed to create ${dest}"
			cp --preserve=mode --dereference -R "${datadir}" "${dest}" || \
				die "Failed to copy ${datadir} to ${dest}"
			chmod -R u=rwX,go=rX "${dest}" || die "Failed to chmod ${dest}"
		done
		popd >/dev/null || die
	fi

	insinto ${TAST_BUNDLE_PREFIX}/share/tast/metadata/${TAST_BUNDLE_TYPE}
	doins "${TAST_BUNDLE_NAME}.pb"
}

EXPORT_FUNCTIONS pkg_setup src_prepare src_compile src_test src_install
