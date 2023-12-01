// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/minios.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <brillo/message_loops/message_loop.h>

#include "minios/process_manager.h"
#include "minios/recovery_installer.h"
#include "minios/state_reporter_interface.h"
#include "minios/utils.h"

namespace minios {

MiniOs::MiniOs(std::shared_ptr<UpdateEngineProxy> update_engine_proxy,
               std::shared_ptr<NetworkManagerInterface> network_manager)
    : update_engine_proxy_(update_engine_proxy),
      network_manager_(network_manager),
      draw_utils_(std::make_shared<DrawUtils>(&process_manager_)),
      screens_controller_(ScreenController(draw_utils_,
                                           update_engine_proxy_,
                                           network_manager_,
                                           &process_manager_)) {}

int MiniOs::Run() {
  LOG(INFO) << "Starting miniOS.";

  if (!screens_controller_.Init()) {
    LOG(ERROR) << AlertLogTag(kCategoryInit) << "Screens init failed. Exiting.";
    return 1;
  }

  return 0;
}

void MiniOs::SetStateReporter(StateReporterInterface* state_reporter) {
  screens_controller_.SetStateReporter(state_reporter);
}

bool MiniOs::GetState(State* state_out, brillo::ErrorPtr* error) {
  screens_controller_.GetState(state_out);
  return true;
}

bool MiniOs::NextScreen(brillo::ErrorPtr* error) {
  return screens_controller_.MoveForward(error);
}

void MiniOs::PressKey(uint32_t in_keycode) {
  screens_controller_.PressKey(in_keycode);
}

bool MiniOs::PrevScreen(brillo::ErrorPtr* error) {
  return screens_controller_.MoveBackward(error);
}

bool MiniOs::Reset(brillo::ErrorPtr* error) {
  return screens_controller_.Reset(error);
}

void MiniOs::SetNetworkCredentials(const std::string& in_ssid,
                                   const std::string& in_passphrase) {
  screens_controller_.SeedNetworkCredentials(in_ssid, in_passphrase);
}

void MiniOs::StartRecovery(const std::string& in_ssid,
                           const std::string& in_passphrase) {
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::BindOnce(&ScreenController::StartRecovery,
                                base::Unretained(&screens_controller_), in_ssid,
                                in_passphrase));
}

}  // namespace minios
