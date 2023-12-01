// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/dlc_helper.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <dbus/scoped_dbus_error.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>

// Needs to be included after dlcservice.pb.h
#include <dlcservice/dbus-proxies.h>  // NOLINT (build/include_alpha)

namespace vm_tools {
namespace concierge {

DlcHelper::DlcHelper(
    std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface> handle)
    : dlcservice_handle_(std::move(handle)) {}

DlcHelper::DlcHelper(const scoped_refptr<dbus::Bus>& bus)
    : DlcHelper(
          std::make_unique<org::chromium::DlcServiceInterfaceProxy>(bus)) {}

DlcHelper::~DlcHelper() = default;

std::optional<std::string> DlcHelper::GetRootPath(const std::string& dlc_id,
                                                  std::string* out_error) {
  DCHECK(out_error);
  dlcservice::DlcState state;
  brillo::ErrorPtr error;

  if (!dlcservice_handle_->GetDlcState(dlc_id, &state, &error)) {
    if (error) {
      *out_error = "Error calling dlcservice (code=" + error->GetCode() +
                   "): " + error->GetMessage();
    } else {
      *out_error = "Error calling dlcservice: unknown";
    }
    return std::nullopt;
  }

  if (state.state() != dlcservice::DlcState_State_INSTALLED) {
    *out_error = dlc_id + " was not installed, its state is: " +
                 std::to_string(state.state()) +
                 " with last error: " + state.last_error_code();
    return std::nullopt;
  }

  return state.root_path();
}

}  // namespace concierge
}  // namespace vm_tools
