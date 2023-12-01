# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# As preparation for making DWARF v5 the default debug information format
# anything that builds with -fno-integrated-as must also build with
# -gdwarf-4, https://crbug.com/1128633 .
cros_pre_src_prepare_force_gdwarf4() {
	export CFLAGS+=" -gdwarf-4"
	export CXXFLAGS+=" -gdwarf-4"
}
