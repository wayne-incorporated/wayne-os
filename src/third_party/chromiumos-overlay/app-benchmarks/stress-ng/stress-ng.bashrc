# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# stress-ng uses -Werror for this single config check, which makes it think we
# don't have `ustat` available.
export MAKEOPTS+=" HAVE_USTAT=1"
