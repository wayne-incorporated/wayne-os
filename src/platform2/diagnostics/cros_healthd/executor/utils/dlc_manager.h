// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DLC_MANAGER_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DLC_MANAGER_H_

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_helpers.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>

namespace dlcservice {
class DlcState;
};  // namespace dlcservice

namespace org::chromium {
class DlcServiceInterfaceProxyInterface;
}  // namespace org::chromium

namespace diagnostics {

// Timeout for getting DLC root path.
// Assuming DLC size is below 3MiB and network speed is above 0.1MiB/s.
constexpr base::TimeDelta kGetDlcRootPathTimeout = base::Seconds(30);

// Interface for accessing verifed DLC and getting DLC root mount path.
class DlcManager {
 public:
  explicit DlcManager(
      org::chromium::DlcServiceInterfaceProxyInterface* dlcservice_proxy);
  DlcManager(const DlcManager&) = delete;
  DlcManager& operator=(const DlcManager&) = delete;
  virtual ~DlcManager() = default;

  using DlcRootPathCallback =
      base::OnceCallback<void(std::optional<base::FilePath>)>;

  void Initialize();

  // Check the DLC state and get its root path. Installation will be triggered
  // if the DLC is unexpectedly missing.
  void GetBinaryRootPath(const std::string& dlc_id,
                         DlcRootPathCallback root_path_cb);

 private:
  enum InitializeState {
    kNotInitialized,
    kInitializing,
    kInitialized,
  };

  // Handle the response of service availability and register the DLC state
  // changed events .
  void RegisterDlcStateChangedEvents(bool service_is_available);

  // Handle the response of registering DLC state changed.
  void HandleRegisterDlcStateChangedResponse(const std::string& interface,
                                             const std::string& signal,
                                             const bool success);

  // Check |initialize_state_| and run |on_initialized| when the state is
  // initialized.
  void WaitForInitialized(base::OnceClosure on_initialized);

  // Install DLC for the |dlc_id|.
  void InstallDlc(const std::string& dlc_id);

  // Handle the response of installing DLC.
  void HandleDlcInstallResponse(const std::string& dlc_id, brillo::Error* err);

  // Handle the DLC state changed signal. Used to check if the DLC installation
  // is complete.
  void OnDlcStateChanged(const dlcservice::DlcState& state);

  // Invoke the pending callbacks for DLC with id |dlc_id|.
  void InvokeRootPathCallbacks(const std::string& dlc_id,
                               std::optional<base::FilePath> root_path);

  // Handle the timeout for getting DLC root path.
  void HandleDlcRootPathCallbackTimeout(const std::string& dlc_id);

  // Unowned pointer that should outlive this instance.
  org::chromium::DlcServiceInterfaceProxyInterface* const dlcservice_proxy_;

  // Pending callbacks that wait for the DLC manager to initialize.
  std::vector<base::OnceClosure> pending_initialized_callbacks_;

  //  The first is DLC ID and the second is pending callbacks for corresponding
  //  DLC.
  std::map<std::string, std::vector<DlcRootPathCallback>>
      pending_root_path_callbacks_;

  // Used to check the initialize state of the DLC manager.
  InitializeState initialize_state_ = kNotInitialized;

  // Must be the last member of the class.
  base::WeakPtrFactory<DlcManager> weak_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_UTILS_DLC_MANAGER_H_
