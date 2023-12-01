// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_CROSSYSTEM_H_
#define CRASH_REPORTER_CROSSYSTEM_H_

#include <libcrossystem/crossystem.h>

namespace crossystem {

// Gets the singleton instance of crossystem::Crossystem that provides
// functionalities to access and modify the system properties.
crossystem::Crossystem* GetInstance();

// Replaces the singleton instance of crossystem::Crossystem for testing.
// It returns the old instance before replacing so that the caller can
// replace it back easily.
crossystem::Crossystem* ReplaceInstanceForTest(
    crossystem::Crossystem* instance);

}  // namespace crossystem

#endif  // CRASH_REPORTER_CROSSYSTEM_H_
