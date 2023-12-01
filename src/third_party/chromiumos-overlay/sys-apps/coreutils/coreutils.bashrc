# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This package doesn't compile with clang-style FORTIFY. Until we can pull
# fixes from upstream, we just disable it. Note that this doesn't disable
# FORTIFY entirely; it just disables the enhanced, clang-specific version.
#
# Fix was accepted upstream as e0953783024a113b186547aca186777f9ce3b798.
export CPPFLAGS+=' -D_CLANG_FORTIFY_DISABLE '
