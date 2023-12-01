# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# With clang-FORTIFY enabled, this package fails to configure. We currently
# have a patch in review for sys-devel/crossdev that will fix this issue. Until
# we can pull that back, we just disable clang's FORTIFY. Note that this
# doesn't disable FORTIFY entirely; it just disables the enhanced,
# clang-specific version.

export CPPFLAGS+=' -D_CLANG_FORTIFY_DISABLE '

# Filter sanitizer flags from bash, https://crbug.com/841954.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}

cros_pre_src_prepare_patches() {
	# Not using ${P} to refer to patch to avoid updating it on every _p# change.
	eapply "${BASHRC_FILESDIR}/${PN}-4.4-noexec.patch" || die

	# This can be dropped for bash 5.2 and later.
	eapply "${BASHRC_FILESDIR}/${PN}-5.1-CVE-2022-3715.patch" || die

	# Disable this logic for SDK builds.
	if [[ $(cros_target) == "cros_host" ]]; then
		CPPFLAGS+=" -DSHELL_IGNORE_NOEXEC"
	else
		# Emit crash reports when we detect problems.
		CPPFLAGS+=" -DSHELL_NOEXEC_CRASH_REPORTS"
		# Don't halt execution for now.
		# TODO(vapier): Remove this once crash report rates go down.
		CPPFLAGS+=" -DSHELL_NOEXEC_REPORT_ONLY"
	fi
	export CPPFLAGS
}
