// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_DBUS_ADAPTORS_DBUS_ADAPTOR_H_
#define DLCSERVICE_DBUS_ADAPTORS_DBUS_ADAPTOR_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <imageloader/proto_bindings/imageloader.pb.h>
#include <imageloader/dbus-proxies.h>

#include "dlcservice/dbus_adaptors/org.chromium.DlcServiceInterface.h"
#include "dlcservice/dlc_service.h"

namespace dlcservice {

class DBusService : public org::chromium::DlcServiceInterfaceInterface {
 public:
  // Will take the ownership of |dlc_service|.
  explicit DBusService(DlcServiceInterface* dlc_service);
  ~DBusService() = default;

  // org::chromium::DlServiceInterfaceInterface overrides:
  bool InstallDlc(brillo::ErrorPtr* err, const std::string& id_in) override;
  bool InstallWithOmahaUrl(brillo::ErrorPtr* err,
                           const std::string& id_in,
                           const std::string& omaha_url_in) override;
  bool Install(brillo::ErrorPtr* err,
               const InstallRequest& install_request) override;
  bool Uninstall(brillo::ErrorPtr* err, const std::string& id_in) override;
  bool Purge(brillo::ErrorPtr* err, const std::string& id_in) override;
  bool GetDlcState(brillo::ErrorPtr* err,
                   const std::string& id_in,
                   DlcState* dlc_state_out) override;
  bool GetInstalled(brillo::ErrorPtr* err,
                    std::vector<std::string>* ids_out) override;
  bool GetExistingDlcs(brillo::ErrorPtr* err,
                       DlcsWithContent* dlc_list_out) override;
  // Only for update_engine to call.
  bool GetDlcsToUpdate(brillo::ErrorPtr* err,
                       std::vector<std::string>* ids_out) override;
  // Only for update_engine to call.
  bool InstallCompleted(brillo::ErrorPtr* err,
                        const std::vector<std::string>& ids_in) override;
  // Only for update_engine to call.
  bool UpdateCompleted(brillo::ErrorPtr* err,
                       const std::vector<std::string>& ids_in) override;

 private:
  DlcServiceInterface* dlc_service_;

  DBusService(const DBusService&) = delete;
  DBusService& operator=(const DBusService&) = delete;
};

class DBusAdaptor : public org::chromium::DlcServiceInterfaceAdaptor,
                    public StateChangeReporterInterface {
 public:
  // Will take the ownership of |dbus_service|.
  explicit DBusAdaptor(std::unique_ptr<DBusService> dbus_service);
  ~DBusAdaptor() override = default;

  // |StateChangeReporterInterface| overrides.
  void DlcStateChanged(const DlcState& dlc_state) override;

 private:
  std::unique_ptr<DBusService> dbus_service_;

  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;
};

}  // namespace dlcservice

#endif  // DLCSERVICE_DBUS_ADAPTORS_DBUS_ADAPTOR_H_
