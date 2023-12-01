// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_PATCHPANEL_DAEMON_H_
#define PATCHPANEL_PATCHPANEL_DAEMON_H_

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/dbus/service_constants.h>
#include <metrics/metrics_library.h>
#include <patchpanel/proto_bindings/patchpanel_service.pb.h>

#include "patchpanel/manager.h"
#include "patchpanel/metrics.h"
#include "patchpanel/patchpanel_adaptor.h"
#include "patchpanel/system.h"

namespace shill {
class ProcessManager;
}  // namespace shill

namespace patchpanel {

// Main class that runs the main loop and responds to D-Bus RPC requests.
class PatchpanelDaemon final : public brillo::DBusServiceDaemon {
 public:
  explicit PatchpanelDaemon(const base::FilePath& cmd_path);
  PatchpanelDaemon(const PatchpanelDaemon&) = delete;
  PatchpanelDaemon& operator=(const PatchpanelDaemon&) = delete;

  ~PatchpanelDaemon() = default;

  // This function is used to enable specific features only on selected
  // combination of Android version, Chrome version, and boards.
  // Empty |supportedBoards| means that the feature should be enabled on all
  // board.
  static bool ShouldEnableFeature(
      int min_android_sdk_version,
      int min_chrome_milestone,
      const std::vector<std::string>& supported_boards,
      const std::string& feature_name);

 protected:
  // Implements brillo::DBusServiceDaemon.
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  // Callback from Daemon to notify that the message loop exits and before
  // Daemon::Run() returns.
  void OnShutdown(int* exit_code) override;

 private:
  // |cached_feature_enabled| stores the cached result of if a feature should be
  // enabled.
  static std::map<const std::string, bool> cached_feature_enabled_;

  // The file path of the patchpanel daemon binary.
  base::FilePath cmd_path_;

  // Unique instance of patchpanel::System shared for all subsystems.
  std::unique_ptr<System> system_;
  // The singleton instance that manages the creation and exit notification of
  // each subprocess. All the subprocesses should be created by this.
  shill::ProcessManager* process_manager_;
  // UMA metrics client.
  std::unique_ptr<MetricsLibraryInterface> metrics_;

  // Patchpanel adaptor.
  std::unique_ptr<PatchpanelAdaptor> adaptor_;
};

}  // namespace patchpanel

#endif  // PATCHPANEL_PATCHPANEL_DAEMON_H_
