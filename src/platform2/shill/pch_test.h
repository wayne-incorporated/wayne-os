// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if defined(SHILL_PCH_TEST_H_)
#error You should not include this header directly in the code.
#endif

#define SHILL_PCH_TEST_H_

// This is the precompiled header for building shill unit test.
// - This header will be prepend to each cc file directly by the compiler, so
//   the code should not include this header directly.
// - It's better not to include any shill headers here, since any change to the
//   included header would trigger a full rebuild, which is not desired.

#include "shill/pch.h"

#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
