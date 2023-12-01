# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Mask install artifacts from abseil and glog dependencies.
# We need only autofdo tools.
absl_mask="
  /usr/lib/pkgconfig/absl_absl_*.pc
"
glog_mask="
  /usr/include/glog
  /usr/lib64/libglog.a
  /usr/lib64/pkgconfig/libglog.pc
  /usr/lib64/cmake/glog
"
PKG_INSTALL_MASK+=" ${absl_mask} ${glog_mask}"
INSTALL_MASK+=" ${absl_mask} ${glog_mask}"
unset absl_mask glog_mask
