// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlcservice/dbus_adaptors/dbus_adaptor.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/stringprintf.h>
#include <brillo/errors/error.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/dlcservice/dbus-constants.h>

#include "dlcservice/dlc_base.h"
#include "dlcservice/error.h"
#include "dlcservice/proto_utils.h"
#include "dlcservice/utils.h"

using std::string;
using std::unique_ptr;
using std::vector;

namespace dlcservice {

DBusService::DBusService(DlcServiceInterface* dlc_service)
    : dlc_service_(dlc_service) {}

bool DBusService::InstallDlc(brillo::ErrorPtr* err, const std::string& id_in) {
  return dlc_service_->Install(
      CreateInstallRequest(id_in, /*omaha_url=*/"", /*reserve=*/false), err);
}

bool DBusService::InstallWithOmahaUrl(brillo::ErrorPtr* err,
                                      const std::string& id_in,
                                      const std::string& omaha_url_in) {
  return dlc_service_->Install(
      CreateInstallRequest(id_in, omaha_url_in, /*reserve=*/false), err);
}

bool DBusService::Install(brillo::ErrorPtr* err,
                          const InstallRequest& install_request) {
  return dlc_service_->Install(install_request, err);
}

bool DBusService::Uninstall(brillo::ErrorPtr* err, const string& id_in) {
  return dlc_service_->Uninstall(id_in, err);
}

// Purge is the same as Uninstall.
bool DBusService::Purge(brillo::ErrorPtr* err, const string& id_in) {
  return dlc_service_->Uninstall(id_in, err);
}

bool DBusService::GetInstalled(brillo::ErrorPtr* err, vector<string>* ids_out) {
  *ids_out = dlc_service_->GetInstalled();
  return true;
}

bool DBusService::GetExistingDlcs(brillo::ErrorPtr* err,
                                  DlcsWithContent* dlc_list_out) {
  DlcIdList ids = dlc_service_->GetExistingDlcs();
  for (const auto& id : ids) {
    const auto* dlc = dlc_service_->GetDlc(id, err);
    auto* dlc_info = dlc_list_out->add_dlc_infos();
    dlc_info->set_id(id);
    dlc_info->set_name(dlc->GetName());
    dlc_info->set_description(dlc->GetDescription());
    dlc_info->set_used_bytes_on_disk(dlc->GetUsedBytesOnDisk());

    // TODO(crbug.com/1092770): This is a very temporarily measure so UI can
    // handle is_removable logic with exceptions for pita. Once the bug is
    // resolved, this logic should change.
    dlc_info->set_is_removable(id != "pita");
  }
  return true;
}

bool DBusService::GetDlcsToUpdate(brillo::ErrorPtr* err,
                                  std::vector<std::string>* ids_out) {
  *ids_out = dlc_service_->GetDlcsToUpdate();
  return true;
}

bool DBusService::GetDlcState(brillo::ErrorPtr* err,
                              const string& id_in,
                              DlcState* dlc_state_out) {
  const auto* dlc = dlc_service_->GetDlc(id_in, err);
  if (dlc == nullptr) {
    return false;
  }
  *dlc_state_out = dlc->GetState();
  return true;
}

bool DBusService::InstallCompleted(brillo::ErrorPtr* err,
                                   const vector<string>& ids_in) {
  return dlc_service_->InstallCompleted(ids_in, err);
}

bool DBusService::UpdateCompleted(brillo::ErrorPtr* err,
                                  const vector<string>& ids_in) {
  return dlc_service_->UpdateCompleted(ids_in, err);
}

DBusAdaptor::DBusAdaptor(unique_ptr<DBusService> dbus_service)
    : org::chromium::DlcServiceInterfaceAdaptor(dbus_service.get()),
      dbus_service_(std::move(dbus_service)) {}

void DBusAdaptor::DlcStateChanged(const DlcState& dlc_state) {
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::BindOnce(&DBusAdaptor::SendDlcStateChangedSignal,
                                base::Unretained(this), dlc_state));
}

}  // namespace dlcservice
