#!/bin/bash -eu
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Script intended to be hacked on by you and run by `git bisect run`, like so:
# `git bisect run ./run_bisection_step.sh`.
#
# Note that `set -e` doesn't play well at all with `git bisect`, but letting
# errors potentially pass silently seems really bad. We don't want to signal to
# `git bisect` that a revision is new because we failed to `mktemp`.
#
# Hence, this script is structured so that you _must_ call one of
# {bisect_new,bisect_old,bisect_skip} before this script exits. These functions
# will all terminate the script immediately. If you do that, this script will
# exit with the appropriate exit code. If not, it'll exit with a code that will
# abort `git bisect`ion.

# Internal details. Feel free to skip to the bottom of this script, which has
# examples/commentary.
BISECT_RESULT=abort

# Make a temporary file for convenience, since it's likely the user will
# need/want it for `grep`ing failing command output/etc.
temp_file=

cleanup() {
	local exit_code=$?

	if [[ -n "${temp_file:-}" ]]; then
		rm -f "${temp_file}" || :
	fi

	local exit_code
	case "${BISECT_RESULT}" in
		abort )
			echo "Internal error: script exited with code ${exit_code}." >&2
			echo "Note: Users should call one of bisect_{old,new,skip} before exiting." >&2
			exit 128
			;;
		old )
			exit_code=0
			;;
		new )
			exit_code=1
			;;
		skip )
			exit_code=125
			;;
		* )
			echo "Internal error: unknown BISECT_RESULT: ${BISECT_RESULT}" >&2
			exit 128
			;;
	esac

	# If we apply patches to Rust sources, we need to clean them up before
	# returning control to `git bisect`. Otherwise, `git bisect`'s next
	# `checkout` may fail due to modified files.
	if ! "${my_dir}/clean_and_sync_rust_root.sh" >& /dev/null; then
		echo "Failed cleaning/syncing Rust root; bisection might fail..." >&2
		# Keep going anyway, knowing that at worst, `git bisect` will simply give up.
	fi
	exit "${exit_code}"
}

trap "cleanup" EXIT

my_dir="$(dirname "$(readlink -m "$0")")"

# Verify that cros-rust is set to build from "${FILESDIR}/rust" enabled. If
# not, `git bisect` is unlikely to do anything of value.
if ! grep -q '^CROS_RUSTC_BUILD_RAW_SOURCES=.' "${my_dir}/../../../../eclass/cros-rustc.eclass"; then
	echo "It seems CROS_RUSTC_BUILD_RAW_SOURCES is unset. This is likely a mistake." >&2
	exit 1
fi

# Running this from outside of the chroot is not supported.
if [[ ! -e /etc/cros_chroot_version ]]; then
  echo "It seems this script was invoked from outside of the chroot. This is unsupported." >&2
  exit 1
fi

temp_file="$(mktemp)"

bisect_old() { BISECT_RESULT=old; exit; }
bisect_new() { BISECT_RESULT=new; exit; }
bisect_skip() { BISECT_RESULT=skip; exit; }

# Instruct dev-lang/rust to use ccache for LLVM builds. This saves considerable
# time on incremental rebuilds.
export FEATURES=ccache

# Start by preparing our source directory. If any of these steps fail, we
# want to abort bisection as a whole; something's gone very wrong.
"${my_dir}/clean_and_sync_rust_root.sh"
"${my_dir}/prepare_rust_for_offline_build.sh"

# Now build Rust, skipping if this revision isn't buildable. Output is tee'd to
# a temp file in case it's useful to you.
#
# If you want to check whether a build failed because patches failed to apply,
# you can do something like:
# ```
# if sudo ebuild $(equery w dev-lang/rust-host) clean configure >& >(tee "${temp_file}"); then
#   bisect_old
# fi
#
# if grep -qF 'Applying Rust patches...' "${temp_file}" && ! grep -qF 'Rust patch application completed successfully' "${temp_file}"; then
#   bisect_new
# fi
# bisect_skip
# ```
#
# In general, it's recommended to `bisect_skip` on failed builds of Rust,
# unless you're trying to troubleshoot something about the actual build of
# dev-lang/rust{,-host}. ToT can always be red.
sudo emerge dev-lang/rust{,-host} >& >(tee "${temp_file}") || bisect_skip

# Put your test-case here. An example might be:
# ```
# setup_board --board=atlas || bisect_skip
# emerge-atlas memd |& tee "${temp_file}"
# if grep -q some-error "${temp_file}"; then
#  bisect_new
# else
#  bisect_old
# fi
# ```
