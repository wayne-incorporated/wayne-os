#!/bin/bash -eu
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script generates a PGO profile for a given Python version.
# PGO profiles are generally pretty stable, so we should only need one per
# minor Python version (3.6, 3.7, ...).
#
# Usage looks like:
#   $0 python-3.6.1

python_version="${1:-}"
if [[ -z "${python_version}" ]]; then
	echo "Please give this script the python \${P} you want to generate" >&2
	echo "a profile for as its first arg. (e.g., python-3.6.12)" >&2
	exit 1
fi

python_ebuild="$(equery w "=dev-lang/${python_version}")"
if [[ -z "${python_ebuild}" ]]; then
	echo "Failed to locate Python ebuild; quit" >&2
	exit 1
fi

tempfile="$(mktemp)"
trap 'rm "${tempfile}"' EXIT

# Note that we *very* intentionally ignore the success of this `ebuild`
# command. It breaks sandbox constraints in a few ways during Python's
# extensive "test everything," phase. As long as the phrase that tells us most
# tests passed is present, be content. A side-benefit of disabling the sandbox
# is that it won't influence our profiles in any way.
FEATURES=-sandbox USE='-pgo_use pgo_generate' \
	ebuild "${python_ebuild}" clean compile |& tee "${tempfile}"

if ! grep -qF "Full build with profile completed successfully." "${tempfile}"; then
	echo "Seems that ebuild-ing python failed somehow?" >&2
	exit 1
fi

# ...Now fish out the profile that's being used. Python always places it
# at ${S}/code.profclangd.
profile_locations=(
	"/var/tmp/portage/dev-lang/${python_version}"*"/work/Python-"*"/code.profclangd"
)

if [[ "${#profile_locations[@]}" -ne 1 ]]; then
	echo "Expected to find 1 profile; got ${#profile_locations[@]}" >&2
	echo "Listed out: ${profile_locations[*]}" >&2
	echo "Maybe rm -rf /var/tmp/portage and try again?" >&2
	exit 1
fi

profile_location="${profile_locations[0]}"
profile_target="${tempfile}.tar"

(cd "$(dirname "${profile_location}")" &&
	tar cf "${profile_target}" code.profclangd)

xz -9 "${profile_target}"
profile_target="${profile_target}.xz"

major_minor_ver="$(cut -d. -f1-2 <<< "${python_version}")"
echo "Profile generated successfully to ${profile_target}."
echo "When ready, please upload that to gs:// with something like"
echo "gsutil cp -n -a public-read ${profile_target}" \
	"gs://chromeos-localmirror/distfiles/${major_minor_ver}-profile.tar.xz"
echo "Once that's done, don't forget to do 'ebuild manifest'."
