// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MINIOS_H_
#define MINIOS_MINIOS_H_

#include <memory>
#include <string>

#include "minios/minios_interface.h"
#include "minios/network_manager_interface.h"
#include "minios/process_manager.h"
#include "minios/screen_controller.h"
#include "minios/state_reporter_interface.h"
#include "minios/update_engine_proxy.h"

namespace minios {

class MiniOs : public MiniOsInterface {
 public:
  explicit MiniOs(std::shared_ptr<UpdateEngineProxy> update_engine_proxy,
                  std::shared_ptr<NetworkManagerInterface> network_manager);
  virtual ~MiniOs() = default;

  // Runs the miniOS flow.
  virtual int Run();

  void SetStateReporter(StateReporterInterface* state_reporter);

  // `MiniOsInterface` overrides.
  bool GetState(State* state_out, brillo::ErrorPtr* error) override;
  bool NextScreen(brillo::ErrorPtr* error) override;
  void PressKey(uint32_t in_keycode) override;
  bool PrevScreen(brillo::ErrorPtr* error) override;
  bool Reset(brillo::ErrorPtr* error) override;
  void SetNetworkCredentials(const std::string& in_ssid,
                             const std::string& in_passphrase) override;
  void StartRecovery(const std::string& in_ssid,
                     const std::string& in_passphrase) override;

 private:
  MiniOs(const MiniOs&) = delete;
  MiniOs& operator=(const MiniOs&) = delete;

  std::shared_ptr<UpdateEngineProxy> update_engine_proxy_;
  std::shared_ptr<NetworkManagerInterface> network_manager_;

  ProcessManager process_manager_;
  std::shared_ptr<DrawInterface> draw_utils_;
  ScreenController screens_controller_;
};

}  // namespace minios

#endif  // MINIOS_MINIOS_H__
