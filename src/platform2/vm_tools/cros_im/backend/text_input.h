// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_TEXT_INPUT_H_
#define VM_TOOLS_CROS_IM_BACKEND_TEXT_INPUT_H_

#ifdef TEST_BACKEND
#include "backend/test/mock_text_input.h"
#else
#include "text-input-extension-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)
#include "text-input-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)
#include "text-input-x11-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)
#endif

#endif  // VM_TOOLS_CROS_IM_BACKEND_TEXT_INPUT_H_
