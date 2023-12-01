# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

abseil-cpp needs to carry the absl.pc.in file and the ebuild is modified to use
that to generate and install a pkg-config metadata file for the package.  This
is needed for libchrome to be inspected by pkg-config.

Due to b/184603259, a workaround in the ebuild is needed to replace instances of
absl:: with absl::ABSL_OPTION_INLINE_NAMESPACE_NAME:: to prevent name conflicts.
