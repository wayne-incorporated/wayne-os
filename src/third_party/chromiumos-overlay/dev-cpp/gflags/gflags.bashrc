# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# gflags_completions.sh is used to autocomplete options in bash when
# used with commands compiled with gflags, but our scripts don't set
# this script in the .bashrc nor do we have bash in all of our boards.
gflags_mask="
  /usr/bin/gflags_completions.sh
"
PKG_INSTALL_MASK+=" ${gflags_mask}"
INSTALL_MASK+=" ${gflags_mask}"
unset gflags_mask
