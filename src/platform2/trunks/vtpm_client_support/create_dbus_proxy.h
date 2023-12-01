// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_VTPM_CLIENT_SUPPORT_CREATE_DBUS_PROXY_H_
#define TRUNKS_VTPM_CLIENT_SUPPORT_CREATE_DBUS_PROXY_H_

#include <memory>

#include "trunks/trunks_dbus_proxy.h"
#include "trunks/trunks_export.h"

namespace trunks {

// Creates a `TrunksDBusProxy` that connects to trunks service.
TRUNKS_EXPORT std::unique_ptr<TrunksDBusProxy> CreateTrunksDBusProxyToTrunks();

// Creates a `TrunksDBusProxy` that connects to vtpm service.
TRUNKS_EXPORT std::unique_ptr<TrunksDBusProxy> CreateTrunksDBusProxyToVtpm();

}  // namespace trunks

#endif  // TRUNKS_VTPM_CLIENT_SUPPORT_CREATE_DBUS_PROXY_H_
