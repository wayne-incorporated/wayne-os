// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/update_engine_proxy.h"

#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>

#include "minios/utils.h"

namespace minios {

namespace {
// Delay reboot after showing screen so user knows recovery has completed.
constexpr int kTimeTillReboot = 10;
}  // namespace

void UpdateEngineProxy::Init() {
  update_engine_proxy_.get()->RegisterStatusUpdateAdvancedSignalHandler(
      base::BindRepeating(&UpdateEngineProxy::OnStatusUpdateAdvancedSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(
          &UpdateEngineProxy::OnStatusUpdateAdvancedSignalConnected,
          weak_ptr_factory_.GetWeakPtr()));
  return;
}

void UpdateEngineProxy::OnStatusUpdateAdvancedSignal(
    const update_engine::StatusResult& status_result) {
  if (!delegate_) {
    LOG(ERROR) << "Delegate not initialized, cannot show screens.";
    return;
  }
  delegate_->OnProgressChanged(status_result);
}

void UpdateEngineProxy::OnStatusUpdateAdvancedSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  if (!success) {
    LOG(ERROR) << "OnStatusUpdateAdvancedSignalConnected not successful";
  }
}

void UpdateEngineProxy::TriggerReboot() {
  brillo::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&UpdateEngineProxy::Reboot,
                     weak_ptr_factory_.GetWeakPtr()),
      base::Seconds(kTimeTillReboot));
}

void UpdateEngineProxy::Reboot() {
  brillo::ErrorPtr error;
  if (!update_engine_proxy_->RebootIfNeeded(&error)) {
    LOG(ERROR) << AlertLogTag(kCategoryReboot)
               << "Could not reboot. ErrorCode=" << error->GetCode()
               << " ErrorMessage=" << error->GetMessage();
  }
}

bool UpdateEngineProxy::StartUpdate() {
  brillo::ErrorPtr error;
  update_engine::UpdateParams update_params;
  update_params.set_app_version("ForcedUpdate");
  update_params.set_omaha_url("");
  update_engine::UpdateFlags* update_flags =
      update_params.mutable_update_flags();
  // Default is interactive as `true`, but explicitly set here.
  update_flags->set_non_interactive(false);

  if (!update_engine_proxy_.get()->Update(update_params, &error)) {
    LOG(ERROR) << AlertLogTag(kCategoryUpdate)
               << "Could not initiate forced update. "
               << "ErrorCode=" << error->GetCode()
               << " ErrorMessage=" << error->GetMessage();
    return false;
  }
  return true;
}

}  // namespace minios
