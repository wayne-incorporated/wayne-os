# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# doxygen is only built for the SDK and needs exceptions enabled to compile.
cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
}
