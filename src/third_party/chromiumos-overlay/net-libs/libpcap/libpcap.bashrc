# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Temporarily disable Wpoison-system-directories till libpcap build
# can be fixed to remove bad include paths, https://crbug.com/1013731 .
cros_pre_src_prepare_disable_poison_system_dirs() {
	export CFLAGS+=" -Wno-poison-system-directories"
	export CXXFLAGS+=" -Wno-poison-system-directories"
}
