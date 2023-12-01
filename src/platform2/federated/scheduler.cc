// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/scheduler.h"

#include <optional>
#include <string>
#include <utility>

#include <base/functional/bind.h>
#include <base/strings/stringprintf.h>
#include <base/system/sys_info.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <dbus/scoped_dbus_error.h>
#include <dlcservice/dbus-proxies.h>

#include "federated/device_status_monitor.h"
#include "federated/federated_library.h"
#include "federated/federated_metadata.h"
#include "federated/metrics.h"
#include "federated/storage_manager.h"
#include "federated/utils.h"

namespace federated {
namespace {

#if USE_LOCAL_FEDERATED_SERVER
constexpr char kServiceUri[] = "https://127.0.0.1:8791";
#else
constexpr char kServiceUri[] = "";
#endif

constexpr char kApiKey[] = "";
constexpr char kDlcId[] = "fcp";
constexpr char kFederatedComputationLibraryName[] = "libfcp.so";
constexpr char kLsbReleaseVersion[] = "CHROMEOS_RELEASE_VERSION";

void OnDBusSignalConnected(const std::string& interface,
                           const std::string& signal,
                           const bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to signal " << signal << " on interface "
               << interface;
  }
}

// Gets release version from base::SysInfo and converts it to the brella lib
// version format, returns std::nullopt if any error. See
// utils.cc::ConvertBrellaLibVersion for more details.
std::optional<std::string> GetClientVersion() {
  std::string release_version;
  if (!base::SysInfo::GetLsbReleaseValue(kLsbReleaseVersion,
                                         &release_version)) {
    LOG(ERROR) << "Cannot get release version";
    return std::nullopt;
  }

  return ConvertBrellaLibVersion(release_version);
}

}  // namespace

Scheduler::~Scheduler() = default;

Scheduler::Scheduler(StorageManager* storage_manager,
                     std::unique_ptr<DeviceStatusMonitor> device_status_monitor,
                     dbus::Bus* bus)
    : storage_manager_(storage_manager),
      device_status_monitor_(std::move(device_status_monitor)),
      dlcservice_client_(
          std::make_unique<org::chromium::DlcServiceInterfaceProxy>(bus)),
      task_runner_(base::SequencedTaskRunner::GetCurrentDefault()),
      scheduling_started_(false),
      weak_ptr_factory_(this) {}

void Scheduler::Schedule(
    const std::optional<base::flat_map<std::string, std::string>>&
        client_launch_stage) {
  if (scheduling_started_) {
    DVLOG(1) << "Scheduling already started, does nothing.";
    return;
  }

  if (client_launch_stage.has_value()) {
    client_launch_stage_ = client_launch_stage.value();
  }

  dlcservice::DlcState dlc_state;
  brillo::ErrorPtr error;
  // Gets current dlc state.
  if (!dlcservice_client_->GetDlcState(kDlcId, &dlc_state, &error)) {
    if (error != nullptr) {
      LOG(ERROR) << "Error calling dlcservice (code=" << error->GetCode()
                 << "): " << error->GetMessage();
      Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcKnownError);
    } else {
      LOG(ERROR) << "Error calling dlcservice: unknown";
      Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcUnknownError);
    }
    return;
  }

  // If installed, calls `ScheduleInternal()` instantly, otherwise triggers dlc
  // install and waits for DlcStateChanged signals.
  if (dlc_state.state() == dlcservice::DlcState::INSTALLED) {
    Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcAlreadyInstalled);
    DVLOG(1) << "dlc fcp is already installed, root path is "
             << dlc_state.root_path();
    ScheduleInternal(dlc_state.root_path());
  } else {
    DVLOG(1) << "dlc fcp isn't installed, call dlc service to install it";
    dlcservice_client_->RegisterDlcStateChangedSignalHandler(
        base::BindRepeating(&Scheduler::OnDlcStateChanged,
                            weak_ptr_factory_.GetMutableWeakPtr()),
        base::BindOnce(&OnDBusSignalConnected));

    error.reset();
    if (!dlcservice_client_->InstallDlc(kDlcId, &error)) {
      if (error != nullptr) {
        LOG(ERROR) << "Error calling dlcservice (code=" << error->GetCode()
                   << "): " << error->GetMessage();
        Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcKnownError);
      } else {
        LOG(ERROR) << "Error calling dlcservice: unknown";
        Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcUnknownError);
      }
    } else {
      Metrics::GetInstance()->LogServiceEvent(
          ServiceEvent::kDlcInstallTriggered);
    }
  }
}

void Scheduler::ScheduleInternal(const std::string& dlc_root_path) {
  if (scheduling_started_) {
    DVLOG(1) << "Scheduling already started, does nothing.";
    return;
  }

  DCHECK(!dlc_root_path.empty()) << "dlc_root_path is empty.";
  DCHECK(clients_.empty()) << "Clients are already scheduled.";

  const std::string lib_path = base::StringPrintf(
      "%s/%s", dlc_root_path.c_str(), kFederatedComputationLibraryName);

  DVLOG(1) << "lib_path is " << lib_path;
  auto* const federated_library = FederatedLibrary::GetInstance(lib_path);
  if (!federated_library->GetStatus().ok()) {
    LOG(ERROR) << "FederatedLibrary failed to initialized with error "
               << federated_library->GetStatus();
    return;
  }

  auto client_configs = GetClientConfig();

  // Pointers to elements of `clients_` are passed to
  // KeepSchedulingJobForClient, which can be invalid if the capacity of
  // `clients_` needs to be increased. Reserves the necessary capacity upfront.
  clients_.reserve(client_configs.size());

  const auto brella_lib_version = GetClientVersion();
  if (!brella_lib_version.has_value()) {
    LOG(ERROR) << "Failed to schedule the tasks because of no valid brella lib "
                  "version";
    return;
  }

  for (auto& kv : client_configs) {
    ClientConfigMetadata& client_config = kv.second;

    // Overwrites the launch_stage if provided by the caller of `Schedule()`.
    const auto iter = client_launch_stage_.find(kv.first);
    if (iter != client_launch_stage_.end()) {
      client_config.launch_stage = iter->second;
    }

    if (client_config.launch_stage.empty()) {
      DVLOG(1) << "client " << kv.first << " has no valid launch_stage, skip.";
      continue;
    }
    clients_.push_back(federated_library->CreateClient(
        kServiceUri, kApiKey, brella_lib_version.value(), client_config,
        device_status_monitor_.get()));
    KeepSchedulingJobForClient(&clients_.back());
  }

  scheduling_started_ = true;
}

void Scheduler::OnDlcStateChanged(const dlcservice::DlcState& dlc_state) {
  DVLOG(1) << "OnDlcStateChanged, dlc_state.id = " << dlc_state.id()
           << ", state = " << dlc_state.state();
  if (!clients_.empty() || dlc_state.id() != kDlcId ||
      dlc_state.state() != dlcservice::DlcState::INSTALLED)
    return;

  DVLOG(1) << "dlc fcp is now installed, root path is "
           << dlc_state.root_path();
  Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kDlcNewlyInstalled);

  ScheduleInternal(dlc_state.root_path());
}

void Scheduler::KeepSchedulingJobForClient(
    FederatedClient* const federated_client) {
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Scheduler::TryToStartJobForClient, base::Unretained(this),
                     federated_client),
      federated_client->next_retry_delay());
}

void Scheduler::TryToStartJobForClient(
    FederatedClient* const federated_client) {
  DVLOG(1) << "In TryToStartJobForClient, client name is "
           << federated_client->GetClientName();
  federated_client->ResetRetryDelay();
  if (!device_status_monitor_->TrainingConditionsSatisfied()) {
    DVLOG(1) << "Device is not in a good condition for training now.";
    Metrics::GetInstance()->LogServiceEvent(ServiceEvent::kTaskSkipped);
    KeepSchedulingJobForClient(federated_client);
    return;
  }

  federated_client->RunPlan(storage_manager_);

  // Posts next task.
  KeepSchedulingJobForClient(federated_client);
}

}  // namespace federated
