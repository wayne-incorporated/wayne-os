// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_AUTHPOLICY_H_
#define AUTHPOLICY_AUTHPOLICY_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <brillo/dbus/async_event_sequencer.h>
#include <install_attributes/libinstallattributes.h>

#include "authpolicy/authpolicy_metrics.h"
#include "authpolicy/org.chromium.AuthPolicy.h"
#include "authpolicy/samba_interface.h"

namespace login_manager {
class PolicyDescriptor;
}

namespace authpolicy {

class ActiveDirectoryAccountInfo;
class Anonymizer;
class AuthPolicyMetrics;
class SessionManagerClient;
class PathService;
class ResponseTracker;

extern const char kChromeUserPolicyType[];
extern const char kChromeDevicePolicyType[];
extern const char kChromeExtensionPolicyType[];

// Implementation of authpolicy's D-Bus interface. Mainly routes stuff between
// D-Bus and SambaInterface.
class AuthPolicy : public org::chromium::AuthPolicyAdaptor,
                   public org::chromium::AuthPolicyInterface {
 public:
  // Args: ErrorType, serialized ActiveDirectoryAccountInfo protobuf.
  using AuthenticateUserResponseCallback = std::unique_ptr<
      brillo::dbus_utils::DBusMethodResponse<int32_t, std::vector<uint8_t>>>;
  // Args: ErrorType.
  using PolicyResponseCallback =
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<int32_t>>;

  // Helper method to get the D-Bus object for the given |object_manager|.
  static std::unique_ptr<brillo::dbus_utils::DBusObject> GetDBusObject(
      brillo::dbus_utils::ExportedObjectManager* object_manager);

  AuthPolicy(AuthPolicyMetrics* metrics, const PathService* path_service);
  AuthPolicy(const AuthPolicy&) = delete;
  AuthPolicy& operator=(const AuthPolicy&) = delete;

  ~AuthPolicy();

  // Initializes internals. See SambaInterface::Initialize() for details.
  [[nodiscard]] ErrorType Initialize(bool device_is_locked);

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction
          completion_callback);

  // Cleans all persistent state files. Returns true if all files were cleared.
  static bool CleanState(const PathService* path_service) {
    return SambaInterface::CleanState(path_service);
  }

  // org::chromium::AuthPolicyInterface: (see org.chromium.AuthPolicy.xml).

  // |auth_user_request_blob| is a serialized AuthenticateUserRequest protobuf.
  // Calls |callback| with an ErrorType and a serialized
  // ActiveDirectoryAccountInfo protobuf.
  void AuthenticateUser(AuthenticateUserResponseCallback callback,
                        const std::vector<uint8_t>& auth_user_request_blob,
                        const base::ScopedFD& password_fd) override;

  // |get_status_request_blob| is a serialized GetUserStatusRequest protobuf.
  // |user_status_blob| is a serialized ActiveDirectoryUserStatus protobuf.
  void GetUserStatus(const std::vector<uint8_t>& get_status_request_blob,
                     int32_t* error,
                     std::vector<uint8_t>* user_status_blob) override;

  // |kerberos_files_blob| is a serialized KerberosFiles protobuf.
  void GetUserKerberosFiles(const std::string& account_id,
                            int32_t* error,
                            std::vector<uint8_t>* kerberos_files_blob) override;

  // |join_domain_request_blob| is a serialized JoinDomainRequest protobuf.
  void JoinADDomain(const std::vector<uint8_t>& join_domain_request_blob,
                    const base::ScopedFD& password_fd,
                    int32_t* error,
                    std::string* joined_domain) override;

  void RefreshUserPolicy(PolicyResponseCallback callback,
                         const std::string& account_id) override;

  void RefreshDevicePolicy(PolicyResponseCallback callback) override;

  std::string SetDefaultLogLevel(int32_t level) override;

  int32_t ChangeMachinePasswordForTesting() override;

  SambaInterface& GetSambaInterfaceForTesting() { return samba_; }

  void SetDeviceIsLockedForTesting() { device_is_locked_ = true; }

  bool IsUserTgtAutoRenewalEnabledForTesting() {
    return samba_.GetUserTgtManagerForTesting()
        .IsTgtAutoRenewalEnabledForTesting();
  }

 private:
  // Gets triggered by when the Kerberos credential cache or the configuration
  // file of the currently logged in user change. Triggers the
  // UserKerberosFilesChanged signal.
  void OnUserKerberosFilesChanged();

  // Sends policy to SessionManager. Assumes |gpo_policy_data| contains user
  // policy if |account_id_key| is not nullptr, otherwise assumes it's device
  // policy.
  void StorePolicy(std::unique_ptr<protos::GpoPolicyData> gpo_policy_data,
                   const std::string* account_id_key,
                   std::unique_ptr<ScopedTimerReporter> timer,
                   PolicyResponseCallback callback);

  // Sends a single policy blob to Session Manager. |policy_type| is the policy
  // type passed into enterprise_management::PolicyData. |policy_blob| is the
  // policy data (serialized Chrome proto or JSON string for extensions). If
  // nullptr, the policy is deleted in Session Manager. |response_tracker| is a
  // data structure to track all responses from Session Manager.
  void StoreSinglePolicy(const login_manager::PolicyDescriptor& descriptor,
                         const char* policy_type,
                         const std::string* policy_blob,
                         scoped_refptr<ResponseTracker> response_tracker);

  AuthPolicyMetrics* metrics_;  // Not owned.
  SambaInterface samba_;

  // Used during enrollment when authpolicyd cannot send policy to Session
  // Manager because device is not locked yet.
  std::unique_ptr<protos::GpoPolicyData> cached_device_policy_data_;
  bool device_is_locked_ = false;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<SessionManagerClient> session_manager_client_;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_AUTHPOLICY_H_
