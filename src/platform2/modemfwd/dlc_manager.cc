// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/dlc_manager.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/errors/error.h>
#include "dlcservice/dbus-proxies.h"
#include "dlcservice/proto_bindings/dlcservice.pb.h"

#include "modemfwd/error.h"

namespace modemfwd {

namespace dlcmanager {
const base::TimeDelta kInstallTimeout = base::Minutes(2);
const base::TimeDelta kGetDlcStatePollPeriod = base::Seconds(1);
const base::TimeDelta kInitialInstallRetryPeriod = base::Seconds(2);
const base::TimeDelta kInstallRetryMaxPeriod = base::Hours(2);
// When the dbus calls don't get stuck, modemfwd will retry
// kMaxRetriesBeforeFallbackToRootfs times before the kInstallTimeout is
// reached. (1+2+4+8+16)*kInitialInstallRetryPeriod = 62 seconds.
const uint16_t kMaxRetriesBeforeFallbackToRootfs = 5;
}  // namespace dlcmanager

DlcManager::DlcManager(scoped_refptr<dbus::Bus> bus,
                       Metrics* metrics,
                       std::map<std::string, Dlc> dlc_per_variant,
                       std::string variant)
    : metrics_(metrics),
      variant_(variant),
      install_retry_period_(dlcmanager::kInitialInstallRetryPeriod),
      install_retry_counter_(0),
      weak_ptr_factory_(this) {
  DCHECK(!variant_.empty());
  Init(dlc_per_variant);
  dlc_service_proxy_ =
      std::make_unique<org::chromium::DlcServiceInterfaceProxy>(bus);
}

// Constructor for testing
DlcManager::DlcManager(
    Metrics* metrics,
    std::map<std::string, Dlc> dlc_per_variant,
    std::string variant,
    std::unique_ptr<org::chromium::DlcServiceInterfaceProxyInterface> proxy)
    : metrics_(metrics),
      variant_(variant),
      install_retry_period_(dlcmanager::kInitialInstallRetryPeriod),
      install_retry_counter_(0),
      weak_ptr_factory_(this) {
  Init(dlc_per_variant);
  dlc_service_proxy_ = std::move(proxy);
}

void DlcManager::Init(std::map<std::string, Dlc> dlc_per_variant) {
  for (const auto& it : dlc_per_variant) {
    if (it.first != variant_) {
      dlcs_to_remove_.emplace(it.second.dlc_id());
    } else {
      dlc_id_ = it.second.dlc_id();
      is_dlc_empty_ = it.second.is_dlc_empty();
    }
  }
}

void DlcManager::RemoveUnecessaryModemDlcs() {
  if (variant_.empty()) {
    LOG(ERROR) << "Cannot remove modem DLCs without knowing the current "
               << "variant";
    auto err = Error::Create(FROM_HERE, error::kUnexpectedEmptyVariant,
                             "Empty variant value");
    metrics_->SendDlcUninstallResultFailure(err.get());
    return;
  }
  dlc_service_proxy_->GetExistingDlcsAsync(
      base::BindOnce(&DlcManager::OnGetExistingDlcsSuccess,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DlcManager::OnGetExistingDlcsError,
                     weak_ptr_factory_.GetWeakPtr()));
}

void DlcManager::OnGetExistingDlcsSuccess(
    const dlcservice::DlcsWithContent& dlc_list) {
  std::set<std::string> dlcs_to_remove_join;
  for (const auto& dlc_info : dlc_list.dlc_infos()) {
    if (dlcs_to_remove_.count(dlc_info.id()))
      dlcs_to_remove_join.emplace(dlc_info.id());
  }
  dlcs_to_remove_ = std::move(dlcs_to_remove_join);
  RemoveNextDlc();
}

void DlcManager::OnGetExistingDlcsError(brillo::Error* dbus_error) {
  brillo::ErrorPtr err = Error::CreateFromDbusError(dbus_error);
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnGetExistingDlcs,
                       "Failed to get existing DLCs.");
  metrics_->SendDlcUninstallResultFailure(err.get());
  // Nothing else to do without the list of existing DLCs.
}

void DlcManager::RemoveNextDlc() {
  if (dlcs_to_remove_.empty()) {
    LOG(INFO) << "No more DLCs to remove";
    return;
  }
  auto it = dlcs_to_remove_.begin();
  LOG(INFO) << "Removing DLC: " << *it;
  dlc_service_proxy_->PurgeAsync(
      *it,
      base::BindOnce(&DlcManager::OnPurgeSuccess,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DlcManager::OnPurgeError,
                     weak_ptr_factory_.GetWeakPtr()));
  dlcs_to_remove_.erase(it);
}

void DlcManager::OnPurgeSuccess() {
  metrics_->SendDlcUninstallResultSuccess();
  RemoveNextDlc();
}

void DlcManager::OnPurgeError(brillo::Error* dbus_error) {
  // If purging the DLC fails, log the error and continue purging the rest.
  brillo::ErrorPtr err = Error::CreateFromDbusError(dbus_error);
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnPurge,
                       "Failed to purge DLC.");
  metrics_->SendDlcUninstallResultFailure(err.get());
  RemoveNextDlc();
}

void DlcManager::InstallModemDlc(InstallModemDlcOnceCallback cb) {
  LOG(INFO) << "Installing DLC:" << dlc_id_;
  CHECK(install_callback_.is_null());
  if (!install_callback_.is_null())
    return;
  install_callback_ = std::move(cb);

  install_step_ = InstallStep::WAITING_FOR_SERVICE;
  install_timeout_callback_.Reset(base::BindOnce(
      &DlcManager::InstallDlcTimedout, weak_ptr_factory_.GetWeakPtr()));
  // Add a timeout in case dlcservice is offline, or the Install call never
  // returns. This will allow modemfwd to continue with other tasks.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, install_timeout_callback_.callback(),
      dlcmanager::kInstallTimeout);

  // modemfwd might start before dlcservice, so it needs to wait until
  // dlcservice shows up in the Dbus before calling |Install|.
  dlc_service_proxy_->GetObjectProxy()->WaitForServiceToBeAvailable(
      base::BindOnce(&DlcManager::OnServiceAvailable,
                     weak_ptr_factory_.GetWeakPtr()));
}

void DlcManager::OnServiceAvailable(bool available) {
  if (!available)
    LOG(WARNING) << "dlcservice not available";

  TryInstall();
}

void DlcManager::PostRetryInstallTask() {
  LOG(INFO) << "Posting DLC install retry task";
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&DlcManager::TryInstall, weak_ptr_factory_.GetWeakPtr()),
      install_retry_period_);

  // Increase the period exponentially until it reaches
  // |kInstallRetryMaxPeriod|.
  if (install_retry_period_ < dlcmanager::kInstallRetryMaxPeriod)
    install_retry_period_ = install_retry_period_ * 2;
}

void DlcManager::TryInstall() {
  install_step_ = InstallStep::INSTALLING;
  dlcservice::InstallRequest install_request;
  install_request.set_id(dlc_id_);
  // set_reserve instructs dlcservice to reserve the space in the stateful
  // partition even when it fails to install the DLC. This ensures that the
  // stateful partition always has room to install the DLC.
  install_request.set_reserve(true);
  dlc_service_proxy_->InstallAsync(
      install_request,
      base::BindOnce(&DlcManager::OnInstallSuccess,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DlcManager::OnInstallError,
                     weak_ptr_factory_.GetWeakPtr()));
}

// When the Install times out, modemfwd should still continue the install flow,
// since the DLC might need to be downloaded from the internet, and this
// process might take a very long time. If the Install flow succeeds later on,
// the DLC will be available the next time modemfwd starts.
void DlcManager::InstallDlcTimedout() {
  brillo::ErrorPtr err;
  switch (install_step_) {
    case InstallStep::WAITING_FOR_SERVICE:
      err = Error::Create(FROM_HERE, error::kTimeoutWaitingForDlcService,
                          "Timeout waiting for dlcservice");
      break;
    case InstallStep::INSTALLING:
      err = Error::Create(FROM_HERE, error::kTimeoutWaitingForDlcInstall,
                          "Timeout installing DLC");
      break;
    case InstallStep::GET_DLC_STATE:
      err = Error::Create(FROM_HERE, error::kTimeoutWaitingForInstalledState,
                          "Timeout while waiting for INSTALLED state.");
      break;
  }

  if (!install_callback_.is_null())
    std::move(install_callback_).Run("", err.get());

  metrics_->SendDlcInstallResultFailure(err.get());
}

void DlcManager::OnInstallSuccess() {
  LOG(INFO) << "DLC install call returned successfully, checking DLC state.";
  install_step_ = InstallStep::GET_DLC_STATE;
  // Because |InstallAsync| only initializes the installation process, we still
  // need to verify that the DLC was actually installed without failures.
  // Also, when the DLC doesn't exist on the device, and has to be downloaded,
  // |Install| returns true and starts the download in the background.
  // When that happens, the state will be |INSTALLING| for some time, and we
  // need to wait until the state changes to |INSTALLED| or |NOT_INSTALLED|.
  CallGetDlcStateAsync();
}

void DlcManager::CallGetDlcStateAsync() {
  dlc_service_proxy_->GetDlcStateAsync(
      dlc_id_,
      base::BindOnce(&DlcManager::OnInstallGetDlcStateSuccess,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&DlcManager::OnInstallGetDlcStateError,
                     weak_ptr_factory_.GetWeakPtr()));
}

void DlcManager::OnInstallError(brillo::Error* dbus_error) {
  brillo::ErrorPtr err = Error::CreateFromDbusError(dbus_error);
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnInstall,
                       "Failed to install DLC.");
  ProcessInstallError(std::move(err));
}

void DlcManager::OnInstallGetDlcStateSuccess(
    const dlcservice::DlcState& state) {
  if (state.state() == dlcservice::DlcState::INSTALLING) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&DlcManager::CallGetDlcStateAsync,
                       base::Unretained(this)),
        dlcmanager::kGetDlcStatePollPeriod);
    return;
  }
  if (state.state() != dlcservice::DlcState::INSTALLED) {
    const std::string& state_name =
        dlcservice::DlcState::State_Name(state.state());
    LOG(INFO) << "DLC not installed correctly. Current state is:" << state_name;
    brillo::ErrorPtr err = Error::Create(
        FROM_HERE, error::kUnexpectedDlcState,
        base::StringPrintf("Unexpected DLC state:%s", state_name.c_str()));
    ProcessInstallError(std::move(err));
    return;
  }

  // Cancel the timeout callback.
  install_timeout_callback_.Cancel();
  if (!install_callback_.is_null())
    std::move(install_callback_).Run(state.root_path(), nullptr);
  metrics_->SendDlcInstallResultSuccess();
}

void DlcManager::OnInstallGetDlcStateError(brillo::Error* dbus_error) {
  brillo::ErrorPtr err = Error::CreateFromDbusError(dbus_error);
  brillo::Error::AddTo(&err, FROM_HERE, kModemfwdErrorDomain,
                       error::kDlcServiceReturnedErrorOnGetDlcState,
                       "Failed to get the state of the DLC.");
  ProcessInstallError(std::move(err));
}

void DlcManager::ProcessInstallError(brillo::ErrorPtr err) {
  if (install_retry_counter_ >= dlcmanager::kMaxRetriesBeforeFallbackToRootfs) {
    // Cancel the timeout callback
    install_timeout_callback_.Cancel();
    if (!install_callback_.is_null())
      std::move(install_callback_).Run("", err.get());

    metrics_->SendDlcInstallResultFailure(err.get());
  }

  install_retry_counter_++;
  PostRetryInstallTask();
}

}  // namespace modemfwd
