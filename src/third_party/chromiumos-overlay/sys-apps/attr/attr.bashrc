# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The lld linker is buggy, so attr forces ld.bfd usage.
# https://bugs.llvm.org/show_bug.cgi?id=51961
cros_pre_src_prepare_use_bfd() {
	LDFLAGS="${LDFLAGS/-Wl,--icf=all}"
}
