// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/shill_client_impl.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <brillo/errors/error.h>
#include <dbus/shill/dbus-constants.h>
#include <shill/dbus-proxies.h>

namespace rmad {

ShillClientImpl::ShillClientImpl(const scoped_refptr<dbus::Bus>& bus) {
  flimflam_manager_proxy_ =
      std::make_unique<org::chromium::flimflam::ManagerProxy>(bus);
}

ShillClientImpl::ShillClientImpl(
    std::unique_ptr<org::chromium::flimflam::ManagerProxyInterface>
        flimflam_manager_proxy)
    : flimflam_manager_proxy_(std::move(flimflam_manager_proxy)) {}

ShillClientImpl::~ShillClientImpl() = default;

bool ShillClientImpl::DisableCellular() const {
  brillo::ErrorPtr error;
  if (!flimflam_manager_proxy_->DisableTechnology(shill::kTypeCellular,
                                                  &error) ||
      error) {
    LOG(ERROR) << "Failed to call DisableTechnology from shill proxy";
    return false;
  }

  // There is no reply. Assume success if there's no errors.
  return true;
}

}  // namespace rmad
