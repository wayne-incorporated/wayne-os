# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

# @ECLASS: cros-fuzzer.eclass
# @MAINTAINER:
# ChromeOS toolchain team <chromeos-toolchain@google.com>

# @DESCRIPTION:
# Ebuild helper functions for fuzzing on Chrome OS.

if [[ -z ${_CROS_FUZZER_ECLASS} ]]; then
_CROS_FUZZER_ECLASS=1

inherit cros-constants flag-o-matic toolchain-funcs

IUSE="fuzzer"

# @FUNCTION: fuzzer-setup-env
# @DESCRIPTION:
# Build a package with fuzzer coverage flags. Safe to use with packages that
# do not build a fuzzer binary e.g. packages that produce shared libraries etc.
fuzzer-setup-env() {
	use fuzzer || return 0
	append-flags "-fsanitize=fuzzer-no-link"
	append-cppflags -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
}

# @FUNCTION: fuzzer-setup-binary
# @DESCRIPTION:
# This function must be called only for ebuilds that only produce
# a fuzzer binary.
fuzzer-setup-binary() {
	use fuzzer || return 0
	fuzzer-setup-env
	append-ldflags "-fsanitize=fuzzer"
}

# @FUNCTION: fuzzer-dir-metadata-component
# @DESCRIPTION:
# Installs the .components file using data from ${S}/DIR_METADATA
fuzzer-dir-metadata-component() {
	local dir_metadata="${S}/DIR_METADATA"
	[[ -f "${dir_metadata}" ]] || return 0
	# Overwrite component file with DIR_METADATA fuzzer_component
	"${DEPOT_TOOLS}/dirmd" parse "${dir_metadata}" \
		| jq ".\"${dir_metadata}\".json.buganizer.componentId" \
		| grep -o '[0-9]*'
}

# @FUNCTION: fuzzer-get-owner-emails
# @DESCRIPTION:
# Takes in an OWNERS filepath and prints out the ClusterFuzz-email-able
# addresses associated with that OWNERS file. Notably, it searches for relevant
# @google.com emails, as we can't email external addresses for security
# reasons. If there's a DIR_METADATA file in the same directory as the OWNERS
# file, it will also output the team_email entry.
# @USAGE: <owners file>
fuzzer-get-owner-emails() {
	local owners_fp="$1"
	[[ -f "${owners_fp}" ]] || die "owners file '${owners_fp}' does not exist"
	local google_email_regex='[[:alnum:]_.+-]+@google.com'
	local owners
	# We don't want to fail here if we don't have any matches.
	# Empty owners files are acceptable.
	owners="$(grep -E "^${google_email_regex}$" "${owners_fp}")"

	local dir_metadata_file
	local dir_metadata_file="${owners_fp%/*}/DIR_METADATA"
	if [[ -f "${dir_metadata_file}" ]]; then
		local dir_metadata_owners
		dir_metadata_owners="$(
			("${DEPOT_TOOLS}/dirmd" parse "${dir_metadata_file}" || die) \
			| jq ".\"${dir_metadata_file}\".json.teamEmail" \
			| grep -Eo "${google_email_regex}")"
		owners+="\n${dir_metadata_owners}"
	fi
	# Because we separate by newline, we need to use printf here.
	printf "%b" "${owners}" | sort -u
}

# @FUNCTION: fuzzer_install
# @DESCRIPTION:
# Installs fuzzer targets in one common location for all fuzzing projects.
# @USAGE: <owners file> <fuzzer binary> [--dict dict_file] \
#   [--comp componentid] [--options options_file] [extra files ...]
fuzzer_install() {
	[[ $# -lt 2 ]] && die "usage: ${FUNCNAME} <OWNERS> <program> " \
		"[--comp componentid] [options] [extra files...]"
	# Don't do anything without USE="fuzzer"
	! use fuzzer && return 0

	local owners=$1
	local prog=$2
	local name="${prog##*/}"
	shift 2

	# Fuzzer option strings.
	local opt_component="comp"
	local opt_dict="dict"
	local opt_option="options"
	# We default reporting to this component:
	# ChromeOS > Security > Machine-found-bugs
	local default_fuzzer_component_id="1099326"

	(
		# Install fuzzer program.
		exeinto "/usr/libexec/fuzzers"
		doexe "${prog}"
		# Install owners file.
		insinto "/usr/libexec/fuzzers"
		fuzzer-get-owner-emails "${owners}" | newins - "${name}.owners"

		local component_id
		component_id="$(fuzzer-dir-metadata-component)"
		component_id="${component_id:-"${default_fuzzer_component_id}"}"
		# Install component file, which can be overwritten later by --comp.
		newins - "${name}.components" <<< "${component_id}"

		# Install other fuzzer files (dict, options file etc.) if provided.
		[[ $# -eq 0 ]] && return 0
		# Parse the arguments.
		local opts=$(getopt -o '' -l "${opt_dict}:,${opt_option}:,${opt_component}:" -- "$@")
		[[ $? -ne 0 ]] && die "fuzzer_install: Incorrect options: $*"
		eval set -- "${opts}"

		while [[ $# -gt 0 ]]; do
		case "$1" in
			"--${opt_dict}")
				newins "$2" "${name}.dict"
				shift 2 ;;
			"--${opt_option}")
				newins "$2" "${name}.options"
				shift 2 ;;
			"--${opt_component}")
				# Overwrite component file with specified component.
				echo "$2" | newins - "${name}.components"
				shift 2 ;;
			--)
				shift ;;
			*)
				doins "$1"
				shift ;;
			esac
		done
	)
}

# @FUNCTION: fuzzer_test
# @DESCRIPTION:
# Runs a fuzzer with a single run and a given seed corpus file or directory.
# @USAGE: <fuzzer binary> <corpus_path>
fuzzer_test() {
	[[ $# -lt 2 ]] && die "usage: ${FUNCNAME} <program> <corpus_path>"

	# Don't do anything without USE="fuzzer"
	! use fuzzer && return 0

	local prog=$1
	local corpus_loc;

	if [[ -f "$2" ]]; then
		[[ "$2" != *.zip ]] && die "Not a zip file: $2"
		# Extract the seed corpus in a temporary location.
		corpus_loc="${T}"/seed_corpus
		unzip "$2" -d "${corpus_loc}"
	elif [[ -d "$2" ]]; then
		corpus_loc="$2"
	else
		die "Invalid seed corpus location $2"
	fi
	"$1" -runs=0 "${corpus_loc}" || die
}

fi
