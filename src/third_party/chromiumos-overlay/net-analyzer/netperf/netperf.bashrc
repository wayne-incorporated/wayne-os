# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# crbug.com/808174 : chromiumos workaround until upstream netperf uses
#     secure method to create temp filenames.
cros_pre_src_configure_netperf_logdir() {
  export CPPFLAGS+=" -DDEBUG_LOG_FILE_DIR='\"/tmp\"'"
}
