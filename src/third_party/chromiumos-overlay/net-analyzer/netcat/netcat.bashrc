# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# b/249835037
# Hack to get around netcat doing int to
# char* conversions everywhere.
cros_pre_src_prepare_disable_warning() {
	export CXXFLAGS="${CXXFLAGS} -Wno-int-conversion"
	export CFLAGS="${CFLAGS} -Wno-int-conversion"
}
