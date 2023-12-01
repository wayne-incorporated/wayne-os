// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_UPDATE_ENGINE_PROXY_H_
#define MINIOS_UPDATE_ENGINE_PROXY_H_

#include <memory>
#include <string>
#include <utility>

#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <update_engine/proto_bindings/update_engine.pb.h>
// NOLINTNEXTLINE(build/include_alpha)
#include <update_engine/dbus-proxies.h>

namespace minios {

class UpdateEngineProxy {
 public:
  explicit UpdateEngineProxy(
      std::unique_ptr<org::chromium::UpdateEngineInterfaceProxyInterface> proxy)
      : update_engine_proxy_(std::move(proxy)),
        delegate_(nullptr),
        weak_ptr_factory_(this) {}
  virtual ~UpdateEngineProxy() = default;

  UpdateEngineProxy(const UpdateEngineProxy&) = delete;
  UpdateEngineProxy& operator=(const UpdateEngineProxy&) = delete;

  class UpdaterDelegate {
   public:
    virtual ~UpdaterDelegate() = default;
    virtual void OnProgressChanged(
        const update_engine::StatusResult& status) = 0;
  };

  // Set callbacks to get update engine status updates.
  virtual void Init();

  virtual void SetDelegate(UpdaterDelegate* delegate) { delegate_ = delegate; }

  // Calls reboot with a delay of `kTimeTillReboot`.
  virtual void TriggerReboot();

  // Forces an interactive update.
  virtual bool StartUpdate();

 private:
  FRIEND_TEST(UpdateEngineProxyTest, AlertOnRebootFailure);

  // Called on receiving update engine's 'Status Update` signal.
  void OnStatusUpdateAdvancedSignal(
      const update_engine::StatusResult& status_result);
  // Called on connecting to update engine's  'Status Update` signal.
  void OnStatusUpdateAdvancedSignalConnected(const std::string& interface_name,
                                             const std::string& signal_name,
                                             bool success);
  // Reboots out of the MiniOs after update engine download and install.
  void Reboot();

  std::unique_ptr<org::chromium::UpdateEngineInterfaceProxyInterface>
      update_engine_proxy_;
  UpdaterDelegate* delegate_;
  base::WeakPtrFactory<UpdateEngineProxy> weak_ptr_factory_;
};

}  // namespace minios

#endif  // MINIOS_UPDATE_ENGINE_PROXY_H_
