// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_OOBE_CONFIG_RESTORE_SERVICE_H_
#define OOBE_CONFIG_OOBE_CONFIG_RESTORE_SERVICE_H_

#include <memory>
#include <utility>
#include <vector>

#include "oobe_config/proto_bindings/oobe_config.pb.h"

#include <brillo/dbus/async_event_sequencer.h>
#include <dbus_adaptors/org.chromium.OobeConfigRestore.h>

namespace oobe_config {

// Implementation of OobeConfigRestore D-Bus interface.
class OobeConfigRestoreService
    : public org::chromium::OobeConfigRestoreAdaptor,
      public org::chromium::OobeConfigRestoreInterface {
 public:
  explicit OobeConfigRestoreService(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object);
  OobeConfigRestoreService(const OobeConfigRestoreService&) = delete;
  OobeConfigRestoreService& operator=(const OobeConfigRestoreService&) = delete;

  ~OobeConfigRestoreService() override;

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  // org::chromium::OobeConfigRestoreInterface
  //   - See org.chromium.OobeConfigRestoreInterface.xml
  void ProcessAndGetOobeAutoConfig(int32_t* error,
                                   OobeRestoreData* oobe_config_blob) override;

 private:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
};

}  // namespace oobe_config

#endif  // OOBE_CONFIG_OOBE_CONFIG_RESTORE_SERVICE_H_
