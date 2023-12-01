# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# kexec-tools fails to build with clang's integrated assembler.
cros_pre_src_prepare_use_gnu_as() {
	tc-is-clang && ASFLAGS+=" -fno-integrated-as"
}
