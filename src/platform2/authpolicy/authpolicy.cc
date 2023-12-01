// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/authpolicy.h"

#include <unordered_set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/authpolicy/dbus-constants.h>
#include <login_manager/proto_bindings/policy_descriptor.pb.h>

#include "authpolicy/authpolicy_metrics.h"
#include "authpolicy/cryptohome_client.h"
#include "authpolicy/log_colors.h"
#include "authpolicy/path_service.h"
#include "authpolicy/proto_bindings/active_directory_info.pb.h"
#include "authpolicy/samba_helper.h"
#include "authpolicy/samba_interface.h"
#include "authpolicy/session_manager_client.h"
#include "bindings/device_management_backend.pb.h"

namespace em = enterprise_management;

using brillo::dbus_utils::DBusObject;
using login_manager::PolicyDescriptor;

namespace authpolicy {

constexpr char kChromeUserPolicyType[] = "google/chromeos/user";
constexpr char kChromeDevicePolicyType[] = "google/chromeos/device";
constexpr char kChromeExtensionPolicyType[] = "google/chrome/extension";

namespace {

// Returns true if the given |domain| is expected to be associated with a
// component id in PolicyDescriptor, e.g. an extension id for
// POLICY_DOMAIN_EXTENSIONS.
bool DomainRequiresComponentId(login_manager::PolicyDomain domain) {
  switch (domain) {
    case login_manager::POLICY_DOMAIN_CHROME:
      return false;
    case login_manager::POLICY_DOMAIN_EXTENSIONS:
    case login_manager::POLICY_DOMAIN_SIGNIN_EXTENSIONS:
      // The component id is the extension id.
      return true;
  }
  NOTREACHED() << "Invalid domain";
}

void PrintResult(const char* msg, ErrorType error) {
  if (error == ERROR_NONE) {
    LOG(INFO) << kColorRequestSuccess << msg << " succeeded" << kColorReset;
  } else {
    LOG(INFO) << kColorRequestFail << msg << " failed with code " << error
              << kColorReset;
  }
}

ErrorMetricType GetPolicyErrorMetricType(bool is_refresh_user_policy) {
  return is_refresh_user_policy ? ERROR_OF_REFRESH_USER_POLICY
                                : ERROR_OF_REFRESH_DEVICE_POLICY;
}

// Serializes |proto| to a vector of bytes. CHECKs for success (should
// never fail if there are no required proto fields).
std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> proto_blob(proto.ByteSizeLong());
  CHECK(proto.SerializeToArray(proto_blob.data(), proto_blob.size()));
  return proto_blob;
}

[[nodiscard]] ErrorType ParseProto(google::protobuf::MessageLite* proto,
                                   const std::vector<uint8_t>& proto_blob) {
  if (!proto->ParseFromArray(proto_blob.data(), proto_blob.size())) {
    LOG(ERROR) << "Failed to parse proto";
    return ERROR_PARSE_FAILED;
  }
  return ERROR_NONE;
}

}  // namespace

// Tracks responses from D-Bus calls to Session Manager's StorePolicy during a
// Refresh*Policy call to AuthPolicy. StorePolicy is called N + 1 times (once
// for the main user/device policy and N times for extension policies, once per
// extension). The Refresh*Policy response callback is only called after all
// StorePolicy responses have been received. This class counts the responses and
// calls the Refresh*Policy response callback after the last response has been
// received. For tracking purposes, a failure to call StorePolicy (e.g. since
// parameters failed to serialize) counts as received response.
class ResponseTracker : public base::RefCountedThreadSafe<ResponseTracker> {
 public:
  ResponseTracker(bool is_refresh_user_policy,
                  int total_response_count,
                  AuthPolicyMetrics* metrics,
                  std::unique_ptr<ScopedTimerReporter> timer,
                  AuthPolicy::PolicyResponseCallback callback)
      : is_refresh_user_policy_(is_refresh_user_policy),
        outstanding_response_count_(total_response_count),
        metrics_(metrics),
        timer_(std::move(timer)),
        callback_(std::move(callback)) {}

  // Should be called when a response finished either successfully or not or if
  // the corresponding StorePolicy call was never made, e.g. due to an error on
  // call parameter setup. If |error_message| is empty, assumes that the
  // StorePolicy call succeeded.
  void OnResponseFinished(bool success) {
    if (!success)
      all_responses_succeeded_ = false;

    // Don't use DCHECK here since bad policy store call counting could have
    // security implications.
    CHECK_GT(outstanding_response_count_, 0);
    if (--outstanding_response_count_ == 0) {
      // This is the last response, call the callback.
      const ErrorMetricType metric_type =
          GetPolicyErrorMetricType(is_refresh_user_policy_);
      ErrorType error =
          all_responses_succeeded_ ? ERROR_NONE : ERROR_STORE_POLICY_FAILED;
      metrics_->ReportError(metric_type, error);
      callback_->Return(error);

      const char* request =
          is_refresh_user_policy_ ? "RefreshUserPolicy" : "RefreshDevicePolicy";
      PrintResult(request, error);

      // Destroy the timer, which triggers the metric. It's going to be
      // destroyed with this instance, anyway, but doing it here explicitly is
      // easier to follow.
      timer_.reset();
    }
  }

 private:
  bool is_refresh_user_policy_;
  int outstanding_response_count_;
  AuthPolicyMetrics* metrics_;  // Not owned.
  std::unique_ptr<ScopedTimerReporter> timer_;
  AuthPolicy::PolicyResponseCallback callback_;
  bool all_responses_succeeded_ = true;
};

// static
std::unique_ptr<DBusObject> AuthPolicy::GetDBusObject(
    brillo::dbus_utils::ExportedObjectManager* object_manager) {
  return std::make_unique<DBusObject>(
      object_manager, object_manager->GetBus(),
      org::chromium::AuthPolicyAdaptor::GetObjectPath());
}

AuthPolicy::AuthPolicy(AuthPolicyMetrics* metrics,
                       const PathService* path_service)
    : org::chromium::AuthPolicyAdaptor(this),
      metrics_(metrics),
      samba_(metrics,
             path_service,
             base::BindRepeating(&AuthPolicy::OnUserKerberosFilesChanged,
                                 base::Unretained(this))) {}

AuthPolicy::~AuthPolicy() = default;

ErrorType AuthPolicy::Initialize(bool device_is_locked) {
  device_is_locked_ = device_is_locked;
  return samba_.Initialize(device_is_locked_ /* expect_config */);
}

void AuthPolicy::RegisterAsync(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  DCHECK(!dbus_object_);
  dbus_object_ = std::move(dbus_object);

  // Make sure the task runner used in some places is actually the D-Bus task
  // runner. This guarantees that tasks scheduled on the task runner won't
  // interfere with D-Bus calls.
  CHECK_EQ(base::SingleThreadTaskRunner::GetCurrentDefault(),
           dbus_object_->GetBus()->GetDBusTaskRunner());
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));

  session_manager_client_ =
      std::make_unique<SessionManagerClient>(dbus_object_.get());

  // Listen to session state changes for backing up user TGT and other data.
  session_manager_client_->ConnectToSessionStateChangedSignal(
      base::BindRepeating(&SambaInterface::OnSessionStateChanged,
                          base::Unretained(&samba_)));

  // Set proper session state.
  samba_.OnSessionStateChanged(session_manager_client_->RetrieveSessionState());

  // Give Samba access to Cryptohome.
  samba_.SetCryptohomeClient(
      std::make_unique<CryptohomeClient>(dbus_object_.get()));
}

void AuthPolicy::AuthenticateUser(
    AuthenticateUserResponseCallback callback,
    const std::vector<uint8_t>& auth_user_request_blob,
    const base::ScopedFD& password_fd) {
  LOG(INFO) << kColorRequest << "Received 'AuthenticateUser' request"
            << kColorReset;
  ScopedTimerReporter timer(TIMER_AUTHENTICATE_USER);
  authpolicy::AuthenticateUserRequest request;
  ErrorType error = ParseProto(&request, auth_user_request_blob);

  ActiveDirectoryAccountInfo account_info;
  if (error == ERROR_NONE) {
    error = samba_.AuthenticateUser(request.user_principal_name(),
                                    request.account_id(), password_fd.get(),
                                    &account_info);
  }

  std::vector<uint8_t> account_info_blob;
  if (error == ERROR_NONE)
    account_info_blob = SerializeProto(account_info);

  PrintResult("AuthenticateUser", error);
  metrics_->ReportError(ERROR_OF_AUTHENTICATE_USER, error);
  callback->Return(static_cast<int>(error), std::move(account_info_blob));

  // Kick off the user affiliation check after responding, so that it can be
  // done in parallel to Chrome startup. The affiliation flag is not needed
  // until user policy fetch.
  if (error == ERROR_NONE)
    samba_.UpdateUserAffiliation();
}

void AuthPolicy::GetUserStatus(
    const std::vector<uint8_t>& get_status_request_blob,
    int32_t* int_error,
    std::vector<uint8_t>* user_status_blob) {
  LOG(INFO) << kColorRequest << "Received 'GetUserStatus' request"
            << kColorReset;
  ScopedTimerReporter timer(TIMER_GET_USER_STATUS);
  authpolicy::GetUserStatusRequest request;
  ErrorType error = ParseProto(&request, get_status_request_blob);

  ActiveDirectoryUserStatus user_status;
  if (error == ERROR_NONE) {
    error = samba_.GetUserStatus(request.user_principal_name(),
                                 request.account_id(), &user_status);
  }
  if (error == ERROR_NONE)
    *user_status_blob = SerializeProto(user_status);

  PrintResult("GetUserStatus", error);
  metrics_->ReportError(ERROR_OF_GET_USER_STATUS, error);
  *int_error = static_cast<int>(error);
}

void AuthPolicy::GetUserKerberosFiles(
    const std::string& account_id,
    int32_t* int_error,
    std::vector<uint8_t>* kerberos_files_blob) {
  LOG(INFO) << kColorRequest << "Received 'GetUserKerberosFiles' request"
            << kColorReset;
  ScopedTimerReporter timer(TIMER_GET_USER_KERBEROS_FILES);

  KerberosFiles kerberos_files;
  ErrorType error = samba_.GetUserKerberosFiles(account_id, &kerberos_files);
  if (error == ERROR_NONE)
    *kerberos_files_blob = SerializeProto(kerberos_files);
  PrintResult("GetUserKerberosFiles", error);
  metrics_->ReportError(ERROR_OF_GET_USER_KERBEROS_FILES, error);
  *int_error = static_cast<int>(error);
}

void AuthPolicy::JoinADDomain(
    const std::vector<uint8_t>& join_domain_request_blob,
    const base::ScopedFD& password_fd,
    int32_t* int_error,
    std::string* joined_domain) {
  LOG(INFO) << kColorRequest << "Received 'JoinADDomain' request"
            << kColorReset;
  ScopedTimerReporter timer(TIMER_JOIN_AD_DOMAIN);

  JoinDomainRequest request;
  ErrorType error = ParseProto(&request, join_domain_request_blob);

  if (error == ERROR_NONE) {
    std::vector<std::string> machine_ou(request.machine_ou().begin(),
                                        request.machine_ou().end());

    error = samba_.JoinMachine(request.machine_name(), request.machine_domain(),
                               machine_ou, request.user_principal_name(),
                               request.kerberos_encryption_types(),
                               password_fd.get(), joined_domain);
  }

  PrintResult("JoinADDomain", error);
  metrics_->ReportError(ERROR_OF_JOIN_AD_DOMAIN, error);
  *int_error = static_cast<int>(error);
}

void AuthPolicy::RefreshUserPolicy(PolicyResponseCallback callback,
                                   const std::string& account_id) {
  LOG(INFO) << kColorRequest << "Received 'RefreshUserPolicy' request"
            << kColorReset;
  auto timer = std::make_unique<ScopedTimerReporter>(TIMER_REFRESH_USER_POLICY);

  // Fetch GPOs for the current user.
  auto gpo_policy_data = std::make_unique<protos::GpoPolicyData>();
  ErrorType error = samba_.FetchUserGpos(account_id, gpo_policy_data.get());

  // Return immediately on error.
  if (error != ERROR_NONE) {
    PrintResult("RefreshUserPolicy", error);
    metrics_->ReportError(ERROR_OF_REFRESH_USER_POLICY, error);
    callback->Return(error);
    return;
  }

  // Send policy to Session Manager.
  const std::string account_id_key = GetAccountIdKey(account_id);
  StorePolicy(std::move(gpo_policy_data), &account_id_key, std::move(timer),
              std::move(callback));
}

void AuthPolicy::RefreshDevicePolicy(PolicyResponseCallback callback) {
  LOG(INFO) << kColorRequest << "Received 'RefreshDevicePolicy' request"
            << kColorReset;
  auto timer =
      std::make_unique<ScopedTimerReporter>(TIMER_REFRESH_DEVICE_POLICY);

  if (cached_device_policy_data_) {
    // Send policy to Session Manager.
    LOG(INFO) << "Using cached policy";
    StorePolicy(std::move(cached_device_policy_data_), nullptr,
                std::move(timer), std::move(callback));
    return;
  }

  // Fetch GPOs for the device.
  auto gpo_policy_data = std::make_unique<protos::GpoPolicyData>();
  ErrorType error = samba_.FetchDeviceGpos(gpo_policy_data.get());

  device_is_locked_ = device_is_locked_ || InstallAttributesReader().IsLocked();
  if (!device_is_locked_ && error == ERROR_NONE) {
    LOG(INFO) << "Device is not locked yet. Caching device policy.";
    cached_device_policy_data_ = std::move(gpo_policy_data);
    error = ERROR_DEVICE_POLICY_CACHED_BUT_NOT_SENT;
  }

  // Return immediately on error.
  if (error != ERROR_NONE) {
    PrintResult("RefreshDevicePolicy", error);
    metrics_->ReportError(ERROR_OF_REFRESH_DEVICE_POLICY, error);
    callback->Return(error);
    return;
  }

  // Send policy to Session Manager.
  StorePolicy(std::move(gpo_policy_data), nullptr, std::move(timer),
              std::move(callback));
}

std::string AuthPolicy::SetDefaultLogLevel(int32_t level) {
  LOG(INFO) << kColorRequest << "Received 'SetDefaultLogLevel' request"
            << kColorReset;
  if (level < AuthPolicyFlags::kMinLevel ||
      level > AuthPolicyFlags::kMaxLevel) {
    std::string message = base::StringPrintf("Level must be between %i and %i.",
                                             AuthPolicyFlags::kMinLevel,
                                             AuthPolicyFlags::kMaxLevel);
    LOG(ERROR) << message;
    return message;
  }
  samba_.SetDefaultLogLevel(static_cast<AuthPolicyFlags::DefaultLevel>(level));
  return std::string();
}

int32_t AuthPolicy::ChangeMachinePasswordForTesting() {
  return samba_.ChangeMachinePasswordForTesting();
}

void AuthPolicy::OnUserKerberosFilesChanged() {
  LOG(INFO) << "Firing signal UserKerberosFilesChanged";
  SendUserKerberosFilesChangedSignal();
}

void AuthPolicy::StorePolicy(
    std::unique_ptr<protos::GpoPolicyData> gpo_policy_data,
    const std::string* account_id_key,
    std::unique_ptr<ScopedTimerReporter> timer,
    PolicyResponseCallback callback) {
  // Build descriptor that specifies where the policy is stored.
  PolicyDescriptor descriptor;
  const bool is_refresh_user_policy = account_id_key != nullptr;
  const char* policy_type = nullptr;
  if (is_refresh_user_policy) {
    DCHECK(!account_id_key->empty());
    descriptor.set_account_type(login_manager::ACCOUNT_TYPE_USER);
    descriptor.set_account_id(*account_id_key);
    policy_type = kChromeUserPolicyType;
  } else {
    descriptor.set_account_type(login_manager::ACCOUNT_TYPE_DEVICE);
    policy_type = kChromeDevicePolicyType;
  }

  // Query IDs of extension policy stored by Session Manager.
  descriptor.set_domain(login_manager::POLICY_DOMAIN_EXTENSIONS);
  std::vector<std::string> existing_extension_ids;
  if (!session_manager_client_->ListStoredComponentPolicies(
          SerializeProto(descriptor), &existing_extension_ids)) {
    // If this call fails, worst thing that can happen is stale extension
    // policy. Still seems better than not pushing policy at all, so keep going.
    existing_extension_ids.clear();
    LOG(WARNING) << "Cannot clean up stale extension policies: "
                    "Failed to get list of stored extension policies.";
  }

  // Extension policies that are no longer coming down from Active Directory
  // have to be deleted. Those are (IDs in Session Manager) - (IDs from AD).
  std::unordered_set<std::string> extension_ids_to_delete;
  extension_ids_to_delete.insert(existing_extension_ids.begin(),
                                 existing_extension_ids.end());
  for (int n = 0; n < gpo_policy_data->extension_policies_size(); ++n)
    extension_ids_to_delete.erase(gpo_policy_data->extension_policies(n).id());

  // Count total number of StorePolicy responses we're expecting and create a
  // tracker object that counts the number of outstanding responses and keeps
  // some unique pointers.
  const int num_extensions_to_store =
      gpo_policy_data->extension_policies_size();
  const int num_extensions_to_delete =
      static_cast<int>(extension_ids_to_delete.size());
  const int num_store_policy_calls =
      1 + num_extensions_to_store + num_extensions_to_delete;
  LOG(INFO) << "Sending " << (is_refresh_user_policy ? "user" : "device")
            << " policy to Session Manager (Chrome policy, "
            << num_extensions_to_store << " extensions). Deleting "
            << num_extensions_to_delete << " stale extensions.";

  scoped_refptr<ResponseTracker> response_tracker =
      new ResponseTracker(is_refresh_user_policy, num_store_policy_calls,
                          metrics_, std::move(timer), std::move(callback));

  // For double checking we counted the number of store calls right.
  int store_policy_call_count = 0;

  // Store the user or device policy.
  descriptor.set_domain(login_manager::POLICY_DOMAIN_CHROME);
  StoreSinglePolicy(descriptor, policy_type,
                    &gpo_policy_data->user_or_device_policy(),
                    response_tracker);
  store_policy_call_count++;

  // Store extension policies.
  descriptor.set_domain(login_manager::POLICY_DOMAIN_EXTENSIONS);
  for (int n = 0; n < num_extensions_to_store; ++n) {
    const protos::ExtensionPolicy& extension_policy =
        gpo_policy_data->extension_policies(n);
    descriptor.set_component_id(extension_policy.id());
    StoreSinglePolicy(descriptor, kChromeExtensionPolicyType,
                      &extension_policy.json_data(), response_tracker);
    store_policy_call_count++;
  }

  // Remove policies for extensions that are no longer coming down from AD.
  descriptor.set_domain(login_manager::POLICY_DOMAIN_EXTENSIONS);
  for (const std::string& extension_id : extension_ids_to_delete) {
    descriptor.set_component_id(extension_id);
    StoreSinglePolicy(descriptor, kChromeExtensionPolicyType,
                      nullptr /* policy_blob */, response_tracker);
    store_policy_call_count++;
  }

  // Don't use DCHECK here since bad policy store call counting could have
  // security implications.
  CHECK(store_policy_call_count == num_store_policy_calls);
}

void AuthPolicy::StoreSinglePolicy(
    const PolicyDescriptor& descriptor,
    const char* policy_type,
    const std::string* policy_blob,
    scoped_refptr<ResponseTracker> response_tracker) {
  // Sending an empty response_blob deletes the policy.
  if (!policy_blob) {
    return;
  }
  // Wrap up the policy in a PolicyFetchResponse.
  em::PolicyData policy_data;
  policy_data.set_policy_value(*policy_blob);
  policy_data.set_policy_type(policy_type);
  if (descriptor.account_type() == login_manager::ACCOUNT_TYPE_USER) {
    policy_data.set_username(samba_.GetUserPrincipal());
    // Device id in the proto also could be used as an account/client id.
    policy_data.set_device_id(samba_.user_account_id());
    if (samba_.is_user_affiliated())
      policy_data.add_user_affiliation_ids(kAffiliationMarker);
  } else {
    DCHECK(descriptor.account_type() == login_manager::ACCOUNT_TYPE_DEVICE);
    policy_data.set_device_id(samba_.machine_name());
    policy_data.add_device_affiliation_ids(kAffiliationMarker);
  }

  // TODO(crbug.com/831995): Use timer that can never run backwards and enable
  // timestamp validation in the Chromium Active Directory policy manager.
  policy_data.set_timestamp(base::Time::Now().ToJavaTime());
  policy_data.set_management_mode(em::PolicyData::ENTERPRISE_MANAGED);
  policy_data.set_machine_name(samba_.machine_name());
  if (DomainRequiresComponentId(descriptor.domain())) {
    DCHECK(!descriptor.component_id().empty());
    policy_data.set_settings_entity_id(descriptor.component_id());
  }

  // Note: No signature required here, Active Directory policy is unsigned!

  em::PolicyFetchResponse policy_response;
  if (!policy_data.SerializeToString(policy_response.mutable_policy_data())) {
    LOG(ERROR) << "Failed to serialize policy data";
    response_tracker->OnResponseFinished(false);
    return;
  }
}

}  // namespace authpolicy
