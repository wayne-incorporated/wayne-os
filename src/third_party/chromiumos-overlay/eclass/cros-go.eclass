# Copyright 2015-2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: cros-go.eclass
# @MAINTAINER:
# The ChromiumOS Authors <chromium-os-dev@chromium.org>
# @BUGREPORTS:
# Please report bugs via https://crbug.com/new (with component "Tools>ChromeOS-Toolchain")
# @VCSURL: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/HEAD/eclass/@ECLASS@
# @BLURB: Eclass for fetching, building, and installing Go packages.
# @DESCRIPTION:
# See http://www.chromium.org/chromium-os/developer-guide/go-in-chromium-os for details.


case ${EAPI} in
[0-6]) die "${ECLASS}: EAPI ${EAPI} not supported" ;;
*) ;;
esac

# @ECLASS-VARIABLE: CROS_GO_SOURCE
# @PRE_INHERIT
# @DESCRIPTION:
# Path to the upstream repository and commit id.
# Go repositories on "github.com" and "*.googlesource.com" are supported.
# The source string contains the path of the git repository containing Go
# packages, and a commit-id (or version tag).
# For example:
#   CROS_GO_SOURCE="github.com/golang/glog 44145f04b68cf362d9c4df2182967c2275eaefed"
# will fetch the sources from https://github.com/golang/glog at the
# specified commit-id, and
#   CROS_GO_SOURCE="github.com/pkg/errors v0.8.0"
# will fetch the sources from https://github.com/pkg/errors at version
# v0.8.0.
# By default, the import path for Go packages in the repository is the
# same as repository path. This can be overridden by appending a colon
# to the repository path, followed by an alternate import path.
# For example:
#   CROS_GO_SOURCE="github.com/go-yaml/yaml:gopkg.in/yaml.v2 v2.2.1"
# will fetch the sources from https://github.com/go-yaml/yaml at version
# v2.2.1, and install the package under "gopkg.in/yaml.v2".
# CROS_GO_SOURCE can contain multiple items when defined as an array:
#   CROS_GO_SOURCE=(
#     "github.com/golang/glog 44145f04b68cf362d9c4df2182967c2275eaefed"
#     "github.com/pkg/errors v0.8.0"
#     "github.com/go-yaml/yaml:gopkg.in/yaml.v2 v2.2.1"
#   )

# @ECLASS-VARIABLE: CROS_GO_WORKSPACE
# @DESCRIPTION:
# Path to the Go workspace, default is ${S}.
# The Go workspace is searched for packages to build and install.
# If all Go packages in a repository are located under "go/src/":
#   CROS_GO_WORKSPACE="${S}/go"
# CROS_GO_WORKSPACE can contain multiple items when defined as an array:
#   CROS_GO_WORKSPACE=(
#     "${S}"
#     "${S}/tast-base"
#   )

# @ECLASS-VARIABLE: CROS_GO_BINARIES
# @DESCRIPTION:
# Go programs to build and install.
# Each program is specified by the path of a directory that
# contains a package "main", or a single Go source file which
# must also contain the package "main". For directories, the
# last component of the package path becomes the name of the
# executable.  For files, the ".go" suffix is also stripped.
# The executable name can be overridden by appending a colon
# to the package path, followed by an alternate name.
# The install path for an executable can be overridden by
# appending a colon to the package path, followed by the
# desired install path/name for it.
# For example:
#   CROS_GO_BINARIES=(
#     "golang.org/x/tools/cmd/godoc"
#     "golang.org/x/tools/cmd/guru:goguru"
#     "golang.org/x/tools/cmd/stringer:/usr/local/bin/gostringer"
#     "golang.org/x/tools/cmd/foo.go"
#     "golang.org/x/tools/cmd/foo.go:gofoo"
#   )
# builds and installs "godoc", "goguru", "gostringer", "foo"
# and "gofoo" binaries.

# Helper function for path and names used in cros-go_src_{compile,install}.
# Returns various views of the information in a CROS_GO_BINARIES entry (a
# "specification" or "spec") separated by colons.
parse_binspec() {
	local spec="$1"
	# Split spec at colon into source and override.
	local source
	local override
	IFS=: read source override empty <<<"${spec}"
	test -z "${empty}" || die "bad CROS_GO_BINARIES entry: \"${spec}\""
	local target
	local installdir
	if [[ -z "${override}" ]] ; then
		target="${spec##*/}"
		# if there is no override, remove .go suffix (if any).
		target="${target%%.go}"
		installdir="/usr/bin"
	else
		# target is the last component of the override path
		target="${override##*/}"
		installdir="${override%/*}"
	fi
	# if the source is a single go file, use its full path name
	if [[ "${source##*.}" == "go" ]]; then
		source="${S}/src/${source}"
	fi
	# there is no colon in any variable, so colon is a safe separator
	echo "${source}:${target}:${installdir}"
}

# @ECLASS-VARIABLE: CROS_GO_VERSION
# @DESCRIPTION:
# Version string to embed in the executable binary.
# The variable main.Version is set to this value at build time.
# For example:
#   CROS_GO_VERSION="${PVR}"
# will set main.Version string variable to package version and
# revision (if any) of the ebuild.

# @ECLASS-VARIABLE: CROS_GO_SKIP_DEP_CHECK
# @DESCRIPTION:
# Temporary workaround to allow circular dependencies like:
# google.golang.org/genproto/googleapis/chromeos/uidetection/v1 requires
# google.golang.org/grpc which requires other packages in
# google.golang.org/genproto
# In the past these have been fixed in GOPATH mode by splitting packages
# in various ebuilds like dev-go/genproto vs dev-go/genproto-rpc (etc.)
# and building them sequentially while ignoring upstream module definitions.
# When switching to Go modules, we need to respect upstream module boundaries
# and let the Go modules dependency system properly handle circular deps.
# So in order to merge for eg dev-go/genproto with dev-go/genproto-rpc, we
# need the temporary ability to relax the dep checking on circular deps.
# This variable addition and use is temporary for the GOPATH -> Go modules
# transition and will go away when switching to modules mode.
# For example:
#   CROS_GO_SKIP_DEP_CHECK="1"

# @ECLASS-VARIABLE: CROS_GO_PACKAGES
# @DESCRIPTION:
# Go packages to install in /usr/lib/gopath.
# Packages are installed in /usr/lib/gopath such that they
# can be imported later from Go code using the exact paths
# listed here. For example:
#   CROS_GO_PACKAGES=(
#     "github.com/golang/glog"
#   )
# will install package files to
#   "/usr/lib/gopath/src/github.com/golang/glog"
# and other Go projects can use the package with
#   import "github.com/golang/glog"
# If the last component of a package path is "...", it is
# expanded to include all Go packages under the directory.

# @ECLASS-VARIABLE: CROS_GO_TEST
# @DESCRIPTION:
# Go packages to test.
# Package tests are run with "-short" flag by default.
# Package tests are always built and run locally on host.
# Default is to test all packages in CROS_GO_WORKSPACE(s).
: ${CROS_GO_TEST:=./...}

# @ECLASS-VARIABLE: CROS_GO_VET
# @DESCRIPTION:
# Go packages to check using "go vet".
# As in CROS_GO_PACKAGES, "..." is expanded.

# @ECLASS-VARIABLE: CROS_GO_VET_FLAGS
# @DESCRIPTION:
# Flags to pass to "go vet" if CROS_GO_VET is set.
# See https://golang.org/cmd/vet/ for available flags.

# @FUNCTION: cros-go_out_dir
# @RETURN: an output directory for compiled CROS_GO_BINARIES
cros-go_out_dir() {
	cros_go_out="${T}/go_output"
	mkdir -p "${cros_go_out}"
	echo "${cros_go_out}"
}

inherit toolchain-funcs

BDEPEND="dev-lang/go"

# @FUNCTION: cros-go_get
# @USAGE: <source> [variables to extract]
# @INTERNAL
# @DESCRIPTION:
# Parse source string and extract different components.
# This function parses the string containing upstream
# repository, import path, and commit id information
# (see description of CROS_GO_SOURCE format above).
# It can also be used to construct the name of the
# distfile and a uri for fetching it.
cros-go_get() {
	local src commit repopath importpath distfile uri
	src="$1"
	commit="${src##* }"
	repopath="${src%% *}"
	importpath="${repopath#*:}"
	repopath="${repopath%:*}"
	distfile="${repopath//\//-}-${commit}.tar.gz"
	uri="https://${repopath}/${commit}.tar.gz"
	case "${repopath%%/*}" in
		github.com)
			uri="https://${repopath}/archive/${commit}.tar.gz" ;;
		*.googlesource.com)
			uri="https://${repopath}/+archive/${commit}.tar.gz" ;;
		*)
			die "Unsupported upstream source in ${repopath}" ;;
	esac

	shift
	local arg
	for arg in "$@" ; do
		case "${arg}" in
			commit) printf "%s" "${commit}" ;;
			repopath) printf "%s" "${repopath}" ;;
			importpath) printf "%s" "${importpath}" ;;
			distfile) printf "%s" "${distfile}" ;;
			uri) printf "%s" "${uri}" ;;
			*) printf "${arg}" ;;
		esac
	done
}

# @FUNCTION: cros-go_src_uri
# @RETURN: a valid SRC_URI for CROS_GO_SOURCE
# @DESCRIPTION:
# Set the SRC_URI in an ebuild with:
#   SRC_URI="$(cros-go_src_uri)"
cros-go_src_uri() {
	local src
	for src in "${CROS_GO_SOURCE[@]}" ; do
		cros-go_get "${src}" uri " -> " distfile "\n"
	done
}

# @FUNCTION: cros-go_pkg_nofetch
# @DESCRIPTION:
# Print useful information on how to download a source tarball and
# add it to chromeos-localmirror.
cros-go_pkg_nofetch() {
	local src
	for src in "${CROS_GO_SOURCE[@]}" ; do
		local uri="$(cros-go_get "${src}" uri)"
		local distfile="$(cros-go_get "${src}" distfile)"
		einfo "Run these commands to add ${distfile} to chromeos-localmirror:"
		einfo "  wget -O ${distfile} ${uri}"
		einfo "  gsutil cp -a public-read ${distfile} gs://chromeos-localmirror/distfiles/"
		einfo
	done
	einfo "After all distfiles have been mirrored, update the 'Manifest' file with:"
	einfo "  ebuild ${EBUILD} manifest"
}

# @FUNCTION: cros-go_src_unpack
# @DESCRIPTION:
# Unpack the source tarball under appropriate location based on
# the desired import path.
cros-go_src_unpack() {
	local src
	for src in "${CROS_GO_SOURCE[@]}" ; do
		local commit="$(cros-go_get "${src}" commit)"
		local repopath="$(cros-go_get "${src}" repopath)"
		local importpath="$(cros-go_get "${src}" importpath)"
		local distfile="$(cros-go_get "${src}" distfile)"

		local destdir="${S}/src/${importpath}"
		case "${repopath%%/*}" in
			github.com)
				# Unpacking tarballs from github creates a top level
				# directory "projectname-version", so extra logic is
				# required to make the contents appear correctly in
				# the desired destination directory.
				mkdir -p "${destdir%/*}" || die
				pushd "${destdir%/*}" >/dev/null || die
				unpack "${distfile}"
				mv "${repopath##*/}-${commit#v}" "${importpath##*/}" || die
				popd >/dev/null || die
				;;
			*.googlesource.com)
				mkdir -p "${destdir}" || die
				pushd "${destdir}" >/dev/null || die
				unpack "${distfile}"
				popd >/dev/null || die
				;;
		esac
	done
}

# @FUNCTION: cros-go_workspace
# @RETURN: Go workspaces, colon separated
# @INTERNAL
# @DESCRIPTION:
# Return the list of workspaces in CROS_GO_WORKSPACE,
# properly formatted for inclusion into GOPATH.
cros-go_workspace() {
	if [[ ${#CROS_GO_WORKSPACE[@]} != 0 ]] ; then
		( IFS=:; echo "${CROS_GO_WORKSPACE[*]}" )
	else
		echo "${S}"
	fi
}

# @FUNCTION: cros-go_gopath
# @RETURN: a valid GOPATH for CROS_GO_WORKSPACE
# @DESCRIPTION:
# Set the GOPATH in an ebuild with:
#   GOPATH="$(cros-go_gopath)"
cros-go_gopath() {
	echo "$(cros-go_workspace):${SYSROOT}/usr/lib/gopath"
}

# @FUNCTION: cros_go
# @DESCRIPTION:
# Wrapper function for invoking the Go tool from an ebuild.
# Sets up GOPATH, and uses the appropriate cross-compiler.
cros_go() {
	GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_gopath)" $(tc-getGO) "$@" || die
}

# @FUNCTION: go_list
# @DESCRIPTION:
# List all Go packages matching a pattern.
# Only list packages in the current workspace.
go_list() {
	GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_workspace)" $(tc-getGO) list "$@" || die
}

# @FUNCTION: go_test
# @DESCRIPTION:
# Wrapper function for building and running unit tests.
# Package tests are always built and run locally on host.
go_test() {
	GO111MODULE=${GO111MODULE:-off} GOPATH="$(cros-go_gopath)" $(tc-getBUILD_GO) test "$@" || die
}

# @FUNCTION: go_vet
# @DESCRIPTION:
# Wrapper function for running "go vet".
go_vet() {
	# shellcheck disable=SC2154
	GO111MODULE="${GO111MODULE:-off}" GOPATH="$(cros-go_gopath)" $(tc-getBUILD_GO) vet \
		"${CROS_GO_VET_FLAGS[@]}" "$@" || die
}

# @FUNCTION: go_lint
# @DESCRIPTION:
# Wrapper function for running "golint"
go_lint() {
	# shellcheck disable=SC2154
	local go_lint_output_base="${CROS_ARTIFACTS_TMP_DIR}/linting_output/go_lint"
	mkdir -p "${go_lint_output_base}"

	local file_name="${1//'/...'/}"
	file_name="${file_name//'/'/-}-$(date +%s)"

	GO111MODULE="${GO111MODULE:-off}" GOPATH="$(cros-go_gopath)" golint \
		"$@" >> "${go_lint_output_base}/${file_name}.txt" || die
}

# @FUNCTION: cros-go_src_compile
# @DESCRIPTION:
# Build CROS_GO_BINARIES.
cros-go_src_compile() {
	out_dir=$(cros-go_out_dir)
	local bin
	local source
	local target
	local installdir
	for bin in "${CROS_GO_BINARIES[@]}" ; do
		einfo "Building \"${bin}\""
		IFS=: read source target installdir <<<"$(parse_binspec "${bin}")"
		cros_go build -v \
			${CROS_GO_VERSION:+"-ldflags=-X main.Version=${CROS_GO_VERSION}"} \
			-o "${out_dir}/${target}" \
			"${source}"
	done

	local pkg
	for pkg in "${CROS_GO_VET[@]}" ; do
		einfo "Vetting \"${pkg}\""
		go_vet "${pkg}"
		# Enable the option to output to a file so that the chromite build API
		# can access Go lints.
		if [[ -n "${ENABLE_GO_LINT}" ]]; then
			go_lint "${pkg}"
		fi
	done
}

# @FUNCTION: cros-go_src_test
# @DESCRIPTION:
# Run tests for packages listed in CROS_GO_TEST.
cros-go_src_test() {
	local pkglist=( $(go_list "${CROS_GO_TEST[@]}") )
	go_test -short "${pkglist[@]}"
}

# @FUNCTION: cros-go_src_install
# @DESCRIPTION:
# Install CROS_GO_BINARIES and CROS_GO_PACKAGES.
cros-go_src_install() {
	out_dir=$(cros-go_out_dir)
	# Install the compiled binaries.
	local bin
	local source
	local target
	local installdir
	for bin in "${CROS_GO_BINARIES[@]}" ; do
		einfo "Installing \"${bin}\""
		IFS=: read source target installdir <<<"$(parse_binspec "${bin}")"
		(
			# Run in sub-shell so we do not modify env.
			exeinto "${installdir}"
			doexe "${out_dir}/${target}"
		)
	done

	# Install the importable packages in /usr/lib/gopath.
	local pkglist=()
	if [[ ${#CROS_GO_PACKAGES[@]} != 0 ]] ; then
		pkglist=( $(go_list "${CROS_GO_PACKAGES[@]}") )
	fi
	local pkg
	for pkg in "${pkglist[@]}" ; do
		einfo "Installing \"${pkg}\""
		local pkgdir="$(go_list -f "{{.Dir}}" "${pkg}")"
		(
			# Run in sub-shell so we do not modify env.
			insinto "/usr/lib/gopath/src/${pkg}"
			local file
			while read -d $'\0' -r file ; do
				doins "${file}"
			done < <(find "${pkgdir}" -maxdepth 1 ! -type d -print0)
		)
	done
}

# @FUNCTION: cros-go_pkg_postinst
# @DESCRIPTION:
# Check for missing dependencies of installed packages.
cros-go_pkg_postinst() {
	# This only works if we're building and installing from source.
	[[ "${MERGE_TYPE}" == "source" ]] || return

	# See CROS_GO_SKIP_DEP_CHECK description for details
	[[ -n "${CROS_GO_SKIP_DEP_CHECK}" ]] && return

	# Get the list of packages from the workspace in ${S}.
	local pkglist=()
	if [[ ${#CROS_GO_PACKAGES[@]} != 0 ]] ; then
		pkglist=( $(go_list "${CROS_GO_PACKAGES[@]}") )
	fi

	# Switch the workspace to where the packages were installed.
	local CROS_GO_WORKSPACE="${SYSROOT}/usr/lib/gopath"

	# For each installed package, check for missing dependencies.
	local pkg
	for pkg in "${pkglist[@]}" ; do
		if [[ $(go_list -f "{{.Incomplete}}" "${pkg}") == "true" ]] ; then
			go_list -f "{{.DepsErrors}}" "${pkg}"
			die "Package has missing dependency: \"${pkg}\""
		fi
	done
}

if [[ ${#CROS_GO_SOURCE[@]} != 0 ]] ; then
	EXPORT_FUNCTIONS pkg_nofetch src_unpack
fi

EXPORT_FUNCTIONS src_compile src_test src_install pkg_postinst
