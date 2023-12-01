# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# gtest doesn't directly use try/catch, but gmock can be instructed to throw an
# exception with testing::Throw(), thus we need to compile it with exceptions
# support.
cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
}
