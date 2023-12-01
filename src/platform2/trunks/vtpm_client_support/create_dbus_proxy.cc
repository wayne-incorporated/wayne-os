// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/vtpm_client_support/create_dbus_proxy.h"

#include <memory>

#include "trunks/trunks_dbus_proxy.h"
#include "trunks/vtpm_client_support/vtpm_dbus_interface.h"

namespace trunks {

std::unique_ptr<TrunksDBusProxy> CreateTrunksDBusProxyToTrunks() {
  return std::make_unique<TrunksDBusProxy>();
}

std::unique_ptr<TrunksDBusProxy> CreateTrunksDBusProxyToVtpm() {
  return std::make_unique<TrunksDBusProxy>(::trunks::vtpm::kVtpmServiceName,
                                           ::trunks::vtpm::kVtpmServicePath,
                                           ::trunks::vtpm::kVtpmInterface);
}

}  // namespace trunks
