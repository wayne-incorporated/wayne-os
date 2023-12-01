// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOMETRICS_MANAGER_WRAPPER_H_
#define BIOD_BIOMETRICS_MANAGER_WRAPPER_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/dbus/exported_object_manager.h>
#include <dbus/message.h>
#include <dbus/object_path.h>

#include "biod/biometrics_manager.h"
#include "biod/session_state_manager.h"

namespace biod {

class BiometricsManagerWrapper : public SessionStateManagerInterface::Observer {
 public:
  BiometricsManagerWrapper(
      std::unique_ptr<BiometricsManager> biometrics_manager,
      brillo::dbus_utils::ExportedObjectManager* object_manager,
      SessionStateManagerInterface* session_state_manager,
      dbus::ObjectPath object_path,
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction
          completion_callback);
  BiometricsManagerWrapper(const BiometricsManagerWrapper&) = delete;
  BiometricsManagerWrapper& operator=(const BiometricsManagerWrapper&) = delete;
  ~BiometricsManagerWrapper() override;

  // Updates the list of records reflected as dbus objects.
  void RefreshRecordObjects();

  // SessionStateManagerInterface::Observer
  void OnUserLoggedIn(const std::string& sanitized_username,
                      bool is_new_login) override;
  void OnUserLoggedOut() override;

 private:
  class RecordWrapper {
   public:
    RecordWrapper(BiometricsManagerWrapper* biometrics_manager,
                  std::unique_ptr<BiometricsManagerRecord> record,
                  brillo::dbus_utils::ExportedObjectManager* object_manager,
                  const dbus::ObjectPath& object_path);
    RecordWrapper(const RecordWrapper&) = delete;
    RecordWrapper& operator=(const RecordWrapper&) = delete;

    ~RecordWrapper();

    const dbus::ObjectPath& path() const { return object_path_; }

    std::string GetUserId() const { return record_->GetUserId(); }

   private:
    bool SetLabel(brillo::ErrorPtr* error, const std::string& new_label);
    bool Remove(brillo::ErrorPtr* error);

    BiometricsManagerWrapper* biometrics_manager_;
    std::unique_ptr<BiometricsManagerRecord> record_;
    brillo::dbus_utils::DBusObject dbus_object_;
    dbus::ObjectPath object_path_;
    brillo::dbus_utils::ExportedProperty<std::string> property_label_;
  };

  void FinalizeEnrollSessionObject();
  void FinalizeAuthSessionObject();

  void OnNameOwnerChanged(dbus::Signal* signal);
  void OnEnrollScanDone(ScanResult scan_result,
                        const BiometricsManager::EnrollStatus& enroll_status);
  void OnAuthScanDone(FingerprintMessage result,
                      BiometricsManager::AttemptMatches matches);
  void OnSessionFailed();
  void EmitStatusChanged(BiometricsManagerStatus status);

  bool StartEnrollSession(brillo::ErrorPtr* error,
                          dbus::Message* message,
                          const std::string& user_id,
                          const std::string& label,
                          dbus::ObjectPath* enroll_session_path);
  bool GetRecordsForUser(brillo::ErrorPtr* error,
                         const std::string& user_id,
                         std::vector<dbus::ObjectPath>* out);
  bool DestroyAllRecords(brillo::ErrorPtr* error);
  bool StartAuthSession(brillo::ErrorPtr* error,
                        dbus::Message* message,
                        dbus::ObjectPath* auth_session_path);

  bool EnrollSessionCancel(brillo::ErrorPtr* error);
  bool AuthSessionEnd(brillo::ErrorPtr* error);

  std::unique_ptr<BiometricsManager> biometrics_manager_;
  SessionStateManagerInterface* session_state_manager_;

  brillo::dbus_utils::DBusObject dbus_object_;
  dbus::ObjectPath object_path_;
  brillo::dbus_utils::ExportedProperty<uint32_t> property_type_;
  std::vector<std::unique_ptr<RecordWrapper>> records_;

  BiometricsManager::EnrollSession enroll_session_;
  std::string enroll_session_owner_;
  dbus::ObjectPath enroll_session_object_path_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> enroll_session_dbus_object_;

  BiometricsManager::AuthSession auth_session_;
  std::string auth_session_owner_;
  dbus::ObjectPath auth_session_object_path_;
  std::unique_ptr<brillo::dbus_utils::DBusObject> auth_session_dbus_object_;
};

}  // namespace biod
#endif  // BIOD_BIOMETRICS_MANAGER_WRAPPER_H_
