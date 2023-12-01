// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/euicc_dbus_adaptor.h"

#include <memory>
#include <string>
#include <utility>

#include <base/strings/string_number_conversions.h>
#include <brillo/errors/error_codes.h>
#include <chromeos/dbus/service_constants.h>

#include "hermes/dbus_result.h"
#include "hermes/euicc.h"

namespace hermes {

namespace {

const char kBasePath[] = "/org/chromium/Hermes/euicc/";

}  // namespace

// static
uint16_t EuiccDBusAdaptor::next_id_ = 0;

EuiccDBusAdaptor::EuiccDBusAdaptor(Euicc* euicc)
    : EuiccAdaptorInterface(this),
      euicc_(euicc),
      object_path_(kBasePath + base::NumberToString(next_id_++)),
      dbus_object_(nullptr, Context::Get()->bus(), object_path_) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAndBlock();
}

void EuiccDBusAdaptor::InstallProfileFromActivationCode(
    std::unique_ptr<DBusResponse<dbus::ObjectPath>> response,
    const std::string& in_activation_code,
    const std::string& in_confirmation_code) {
  DbusResult<dbus::ObjectPath> dbus_result(std::move(response));
  euicc_->InstallProfileFromActivationCode(
      in_activation_code, in_confirmation_code, std::move(dbus_result));
}

void EuiccDBusAdaptor::InstallPendingProfile(
    std::unique_ptr<DBusResponse<dbus::ObjectPath>> response,
    const dbus::ObjectPath& in_pending_profile,
    const std::string& in_confirmation_code) {
  DbusResult<dbus::ObjectPath> dbus_result(std::move(response));
  euicc_->InstallPendingProfile(in_pending_profile, in_confirmation_code,
                                std::move(dbus_result));
}

void EuiccDBusAdaptor::UninstallProfile(
    std::unique_ptr<DBusResponse<>> response,
    const dbus::ObjectPath& in_profile) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->UninstallProfile(in_profile, std::move(dbus_result));
}

void EuiccDBusAdaptor::RequestPendingProfiles(
    std::unique_ptr<DBusResponse<>> response, const std::string& in_root_smds) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->RequestPendingProfiles(std::move(dbus_result), in_root_smds);
}

void EuiccDBusAdaptor::RefreshSmdxProfiles(
    std::unique_ptr<DBusResponse<std::vector<dbus::ObjectPath>, std::string>>
        response,
    const std::string& activation_code,
    bool should_not_switch_slot) {
  DbusResult<std::vector<dbus::ObjectPath>, std::string> dbus_result(
      std::move(response));
  euicc_->RefreshSmdxProfiles(std::move(dbus_result), activation_code,
                              should_not_switch_slot);
}

void EuiccDBusAdaptor::RequestInstalledProfiles(
    std::unique_ptr<DBusResponse<>> response) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->RefreshInstalledProfiles(false /* should_not_switch_slot */,
                                   std::move(dbus_result));
}

void EuiccDBusAdaptor::RefreshInstalledProfiles(
    std::unique_ptr<DBusResponse<>> response, bool should_not_switch_slot) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->RefreshInstalledProfiles(should_not_switch_slot,
                                   std::move(dbus_result));
}

void EuiccDBusAdaptor::SetTestMode(std::unique_ptr<DBusResponse<>> response,
                                   bool in_is_test_mode) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->SetTestModeHelper(in_is_test_mode, std::move(dbus_result));
}

void EuiccDBusAdaptor::UseTestCerts(bool in_use_test_certs) {
  euicc_->UseTestCerts(in_use_test_certs);
}

void EuiccDBusAdaptor::ResetMemory(std::unique_ptr<DBusResponse<>> response,
                                   int in_reset_options) {
  DbusResult<> dbus_result(std::move(response));
  euicc_->ResetMemoryHelper(std::move(dbus_result), in_reset_options);
}

void EuiccDBusAdaptor::IsTestEuicc(
    std::unique_ptr<DBusResponse<bool>> response) {
  DbusResult<bool> dbus_result(std::move(response));
  euicc_->IsTestEuicc(std::move(dbus_result));
}

}  // namespace hermes
