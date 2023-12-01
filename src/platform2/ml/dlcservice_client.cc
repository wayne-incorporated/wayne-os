// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dlcservice_client.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/dlcservice/dbus-constants.h>
#include <dbus/message.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>

namespace ml {

void DlcserviceClient::GetDlcRootPath(const std::string& dlc_id,
                                      GetDlcRootPathCallback callback) {
  // Construct the dbus call.
  dbus::MethodCall method_call(dlcservice::kDlcServiceInterface,
                               dlcservice::kGetDlcStateMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(dlc_id);

  // Make the call.
  dlcservice_proxy_->CallMethodWithErrorResponse(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&OnGetDlcStateComplete, std::move(callback)));
}

DlcserviceClient::DlcserviceClient(dbus::Bus* bus)
    : dlcservice_proxy_(bus->GetObjectProxy(
          dlcservice::kDlcServiceServiceName,
          dbus::ObjectPath(dlcservice::kDlcServiceServicePath))) {}

// Calls `callback` either on root_path or empty string based on the `response`.
void DlcserviceClient::OnGetDlcStateComplete(
    GetDlcRootPathCallback callback,
    dbus::Response* response,
    dbus::ErrorResponse* err_response) {
  dlcservice::DlcState dlc_state;
  if (!response ||
      !dbus::MessageReader(response).PopArrayOfBytesAsProto(&dlc_state)) {
    LOG(ERROR) << "GetDlcState error " << err_response->GetErrorName();
    std::move(callback).Run(std::string());
    return;
  }
  if (dlc_state.state() != dlcservice::DlcState::INSTALLED) {
    LOG(ERROR) << "GetDlcRootPath error, dlc not installed with error "
               << dlc_state.last_error_code() << " and state "
               << dlc_state.state();
    std::move(callback).Run(std::string());
    return;
  }
  std::move(callback).Run(dlc_state.root_path());
}

}  // namespace ml
