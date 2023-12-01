// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CROS_IM_BACKEND_WAYLAND_CLIENT_H_
#define VM_TOOLS_CROS_IM_BACKEND_WAYLAND_CLIENT_H_

#ifdef TEST_BACKEND
#include "backend/test/mock_wayland_client.h"
#else
#include <wayland-client.h>
#include <wayland-client-protocol.h>
#endif

#endif  // VM_TOOLS_CROS_IM_BACKEND_WAYLAND_CLIENT_H_
