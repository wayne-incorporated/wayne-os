// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_DLC_MANAGER_H_
#define MODEMFWD_DLC_MANAGER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/cancelable_callback.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include "brillo/errors/error.h"
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <dlcservice/dbus-proxies.h>

#include "modemfwd/metrics.h"
#include "modemfwd/proto_bindings/firmware_manifest_v2.pb.h"

namespace dbus {
class Bus;
}  // namespace dbus

namespace modemfwd {

namespace dlcmanager {
// Maximum time to wait for dlcservice to show up on the Dbus and Install
// the DLC.
extern const base::TimeDelta kInstallTimeout;

// GetDlcState polling period.
extern const base::TimeDelta kGetDlcStatePollPeriod;

// Number of retries before falling back to rootfs.
extern const uint16_t kMaxRetriesBeforeFallbackToRootfs;

// The initial value for retry period.
extern const base::TimeDelta kInitialInstallRetryPeriod;
// Max value for the install retry period.
extern const base::TimeDelta kInstallRetryMaxPeriod;
}  // namespace dlcmanager
using InstallModemDlcOnceCallback =
    base::OnceCallback<void(const std::string&, const brillo::Error*)>;
class DlcManager {
 public:
  explicit DlcManager(scoped_refptr<dbus::Bus> bus,
                      Metrics* metrics,
                      std::map<std::string, Dlc> dlc_per_variant,
                      std::string variant);

  virtual ~DlcManager() = default;

  // Removes all modemfwd DLCs except the corresponding one for the device's
  // variant.
  virtual void RemoveUnecessaryModemDlcs();

  // Install and mount the DLC corresponding to the device's variant.
  // Returns the mount location of the DLC. Returns an empty path on failure.
  // This function waits for the dlcservice to be running before calling
  // Install to avoid race conditions.
  // This function is meant to be called only once.
  virtual void InstallModemDlc(InstallModemDlcOnceCallback cb);

  const virtual std::string& DlcId() { return dlc_id_; }
  const virtual bool IsDlcEmpty() { return is_dlc_empty_; }

 protected:
  // For testing
  DlcManager() = default;
  explicit DlcManager(
      Metrics* metrics,
      std::map<std::string, Dlc> dlc_per_variant,
      std::string variant,
      std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface> proxy);

 private:
  void Init(std::map<std::string, Dlc> dlc_per_variant);
  void OnServiceAvailable(bool available);
  void InstallDlcTimedout();
  void TryInstall();
  void PostRetryInstallTask();

  void RemoveNextDlc();

  void OnGetExistingDlcsSuccess(const dlcservice::DlcsWithContent& dlc_list);
  void OnGetExistingDlcsError(brillo::Error* dbus_error);
  void OnPurgeSuccess();
  void OnPurgeError(brillo::Error* dbus_error);
  void OnInstallSuccess();
  void OnInstallError(brillo::Error* dbus_error);
  void CallGetDlcStateAsync();
  void OnInstallGetDlcStateSuccess(const dlcservice::DlcState& state);
  void OnInstallGetDlcStateError(brillo::Error* dbus_error);
  void ProcessInstallError(brillo::ErrorPtr error);

  enum class InstallStep { WAITING_FOR_SERVICE, INSTALLING, GET_DLC_STATE };
  std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface>
      dlc_service_proxy_;
  Metrics* metrics_;
  std::set<std::string> dlcs_to_remove_;
  std::string dlc_id_;
  bool is_dlc_empty_;
  std::string variant_;
  // Since the device might not have internet when modemfwd starts, modemfwd
  // should try to install periodically until Install succeeds. This is only
  // used after a powerwash, when the DLCs are not in the device. The period
  // increases on each failure to avoid constant retries.
  base::TimeDelta install_retry_period_;
  uint16_t install_retry_counter_;

  InstallStep install_step_;
  InstallModemDlcOnceCallback install_callback_;
  base::CancelableOnceClosure install_timeout_callback_;

  base::WeakPtrFactory<DlcManager> weak_ptr_factory_{this};
};

}  // namespace modemfwd
#endif  // MODEMFWD_DLC_MANAGER_H_
