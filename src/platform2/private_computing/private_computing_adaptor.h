// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRIVATE_COMPUTING_PRIVATE_COMPUTING_ADAPTOR_H_
#define PRIVATE_COMPUTING_PRIVATE_COMPUTING_ADAPTOR_H_

#include <memory>
#include <vector>

#include <base/files/file_util.h>
#include <brillo/dbus/async_event_sequencer.h>
#include "private_computing/org.chromium.PrivateComputing.h"
#include "private_computing/proto_bindings/private_computing_service.pb.h"

namespace brillo::dbus_utils {
class DBusObject;
}  // namespace brillo::dbus_utils

namespace private_computing {

class PrivateComputingAdaptor
    : public org::chromium::PrivateComputingAdaptor,
      public org::chromium::PrivateComputingInterface {
 public:
  explicit PrivateComputingAdaptor(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object);
  PrivateComputingAdaptor(const PrivateComputingAdaptor&) = delete;
  PrivateComputingAdaptor& operator=(const PrivateComputingAdaptor&) = delete;
  ~PrivateComputingAdaptor() override = default;

  // Register the D-Bus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  // org::chromium::PrivateComputingInterface.
  // Get the device last ping dates and save it to a file in |/var/lib/|.
  std::vector<uint8_t> SaveLastPingDatesStatus(
      const std::vector<uint8_t>& request_blob) override;

  std::vector<uint8_t> GetLastPingDatesStatus() override;

  void SetVarLibDirForTest(const base::FilePath& dir) { var_lib_dir_ = dir; }

  void SetPreserveDirForTest(const base::FilePath& dir) { preserve_dir_ = dir; }

 private:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  // Base sysfs directory save the status after every successful ping.
  base::FilePath var_lib_dir_;
  // Base sysfs directory to preserve the status after powerwash.
  base::FilePath preserve_dir_;
};

}  // namespace private_computing

#endif  // PRIVATE_COMPUTING_PRIVATE_COMPUTING_ADAPTOR_H_
