// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/patchpanel_daemon.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <algorithm>
#include <set>
#include <utility>

#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/key_value_store.h>
#include <metrics/metrics_library.h>
#include <shill/net/process_manager.h>

#include "patchpanel/ipc.h"
#include "patchpanel/metrics.h"
#include "patchpanel/net_util.h"
#include "patchpanel/proto_utils.h"
#include "patchpanel/shill_client.h"

namespace patchpanel {

PatchpanelDaemon::PatchpanelDaemon(const base::FilePath& cmd_path)
    : DBusServiceDaemon(kPatchPanelServiceName),
      cmd_path_(cmd_path),
      system_(std::make_unique<System>()),
      process_manager_(shill::ProcessManager::GetInstance()),
      metrics_(std::make_unique<MetricsLibrary>()) {}

std::map<const std::string, bool> PatchpanelDaemon::cached_feature_enabled_ =
    {};

bool PatchpanelDaemon::ShouldEnableFeature(
    int min_android_sdk_version,
    int min_chrome_milestone,
    const std::vector<std::string>& supported_boards,
    const std::string& feature_name) {
  static const char kLsbReleasePath[] = "/etc/lsb-release";

  const auto& cached_result = cached_feature_enabled_.find(feature_name);
  if (cached_result != cached_feature_enabled_.end())
    return cached_result->second;

  auto check = [min_android_sdk_version, min_chrome_milestone,
                &supported_boards, &feature_name]() {
    brillo::KeyValueStore store;
    if (!store.Load(base::FilePath(kLsbReleasePath))) {
      LOG(ERROR) << "Could not read lsb-release";
      return false;
    }

    std::string value;
    if (!store.GetString("CHROMEOS_ARC_ANDROID_SDK_VERSION", &value)) {
      LOG(ERROR) << feature_name
                 << " disabled - cannot determine Android SDK version";
      return false;
    }
    int ver = 0;
    if (!base::StringToInt(value.c_str(), &ver)) {
      LOG(ERROR) << feature_name << " disabled - invalid Android SDK version";
      return false;
    }
    if (ver < min_android_sdk_version) {
      LOG(INFO) << feature_name << " disabled for Android SDK " << value;
      return false;
    }

    if (!store.GetString("CHROMEOS_RELEASE_CHROME_MILESTONE", &value)) {
      LOG(ERROR) << feature_name
                 << " disabled - cannot determine ChromeOS milestone";
      return false;
    }
    if (!base::StringToInt(value.c_str(), &ver)) {
      LOG(ERROR) << feature_name << " disabled - invalid ChromeOS milestone";
      return false;
    }
    if (ver < min_chrome_milestone) {
      LOG(INFO) << feature_name << " disabled for ChromeOS milestone " << value;
      return false;
    }

    if (!store.GetString("CHROMEOS_RELEASE_BOARD", &value)) {
      LOG(ERROR) << feature_name << " disabled - cannot determine board";
      return false;
    }
    if (!supported_boards.empty() &&
        std::find(supported_boards.begin(), supported_boards.end(), value) ==
            supported_boards.end()) {
      LOG(INFO) << feature_name << " disabled for board " << value;
      return false;
    }
    return true;
  };

  bool result = check();
  cached_feature_enabled_.emplace(feature_name, result);
  return result;
}

void PatchpanelDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  // Initialize |process_manager_| before creating subprocesses.
  process_manager_->Init();

  auto rtnl_client = RTNLClient::Create();
  if (!rtnl_client) {
    LOG(ERROR) << "Failed to create RTNLClient, abort registering the adaptor";
    return;
  }

  adaptor_ = std::make_unique<PatchpanelAdaptor>(
      cmd_path_, bus_, system_.get(), process_manager_, metrics_.get(),
      std::move(rtnl_client));
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

void PatchpanelDaemon::OnShutdown(int* exit_code) {
  LOG(INFO) << "Shutting down and cleaning up";

  adaptor_.reset();

  // Stop |process_manager_| after subprocesses are finished.
  process_manager_->Stop();

  if (bus_) {
    bus_->ShutdownAndBlock();
  }
  brillo::DBusDaemon::OnShutdown(exit_code);
}

}  // namespace patchpanel
