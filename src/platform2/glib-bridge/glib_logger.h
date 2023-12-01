// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This sets up the default glib logger so it logs with the libchrome
// logger instead.

#ifndef GLIB_BRIDGE_GLIB_LOGGER_H_
#define GLIB_BRIDGE_GLIB_LOGGER_H_

#include <string>

#include "glib-bridge/glib_bridge_export.h"

namespace glib_bridge {

GLIB_BRIDGE_EXPORT void ForwardLogs();

}  // namespace glib_bridge

#endif  // GLIB_BRIDGE_GLIB_LOGGER_H_
