// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/kerberos_adaptor.h"

#include <optional>
#include <string>
#include <unordered_set>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>
#include <dbus/login_manager/dbus-constants.h>
#include <libpasswordprovider/password_provider.h>
#include <session_manager/dbus-proxies.h>

#include "kerberos/account_manager.h"
#include "kerberos/error_strings.h"
#include "kerberos/kerberos_metrics.h"
#include "kerberos/krb5_interface.h"
#include "kerberos/krb5_interface_impl.h"
#include "kerberos/krb5_jail_wrapper.h"
#include "kerberos/platform_helper.h"

namespace kerberos {

namespace {

constexpr base::TimeDelta kTicketExpiryCheckDelay = base::Seconds(3);

using ByteArray = KerberosAdaptor::ByteArray;

// Serializes |proto| to a vector of bytes. CHECKs for success (should
// never fail if there are no required proto fields).
ByteArray SerializeProto(const google::protobuf::MessageLite& proto) {
  ByteArray proto_blob(proto.ByteSizeLong());
  CHECK(proto.SerializeToArray(proto_blob.data(), proto_blob.size()));
  return proto_blob;
}

// Parses a proto from an array of bytes |proto_blob|. Returns
// ERROR_PARSE_REQUEST_FAILED on error.
[[nodiscard]] ErrorType ParseProto(google::protobuf::MessageLite* proto,
                                   const ByteArray& proto_blob) {
  if (!proto->ParseFromArray(proto_blob.data(), proto_blob.size())) {
    LOG(ERROR) << "Failed to parse proto";
    return ERROR_PARSE_REQUEST_FAILED;
  }
  return ERROR_NONE;
}

void PrintRequest(const char* method_name) {
  LOG(INFO) << ">>> " << method_name;
}

void PrintResult(const char* method_name, ErrorType error) {
  if (error == ERROR_NONE)
    LOG(INFO) << "<<< " << method_name << " succeeded";
  else
    LOG(ERROR) << "<<< " << method_name << " failed: " << GetErrorString(error);
}

// Calls Session Manager to get the user hash for the primary session. Returns
// an empty string and logs on error.
std::string GetSanitizedUsername(brillo::dbus_utils::DBusObject* dbus_object) {
  std::string username;
  std::string sanitized_username;
  brillo::ErrorPtr error;
  org::chromium::SessionManagerInterfaceProxy proxy(dbus_object->GetBus());
  if (!proxy.RetrievePrimarySession(&username, &sanitized_username, &error)) {
    const char* error_msg =
        error ? error->GetMessage().c_str() : "Unknown error.";
    LOG(ERROR) << "Call to RetrievePrimarySession failed. " << error_msg;
    return std::string();
  }
  return sanitized_username;
}

}  // namespace

KerberosAdaptor::KerberosAdaptor(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object)
    : org::chromium::KerberosAdaptor(this),
      dbus_object_(std::move(dbus_object)) {}

KerberosAdaptor::~KerberosAdaptor() = default;

void KerberosAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));

  // Get the sanitized username (aka user hash). It's needded to determine the
  // daemon store directory where account data is stored.
  base::FilePath storage_dir;
  if (storage_dir_for_testing_) {
    storage_dir = *storage_dir_for_testing_;
  } else {
    const std::string sanitized_username =
        GetSanitizedUsername(dbus_object_.get());
    if (!sanitized_username.empty()) {
      storage_dir = base::FilePath("/run/daemon-store/kerberosd/")
                        .Append(sanitized_username);
    } else {
      // /tmp is a tmpfs and the daemon is shut down on logout, so data is
      // cleared on logout. Better than nothing, though.
      storage_dir = base::FilePath("/tmp");
      LOG(ERROR) << "Failed to retrieve user hash to determine storage "
                    "directory. Falling back to "
                 << storage_dir.value() << ".";
    }
  }

  // Might have already been set for testing.
  if (!metrics_)
    metrics_ = std::make_unique<KerberosMetrics>(storage_dir);

  // Create krb5 or use the one given for testing.
  auto krb5 = krb5_for_testing_ ? std::move(krb5_for_testing_)
                                : std::make_unique<Krb5JailWrapper>(
                                      std::make_unique<Krb5InterfaceImpl>());

  manager_ = std::make_unique<AccountManager>(
      storage_dir,
      base::BindRepeating(&KerberosAdaptor::OnKerberosFilesChanged,
                          base::Unretained(this)),
      base::BindRepeating(&KerberosAdaptor::OnKerberosTicketExpiring,
                          base::Unretained(this)),
      std::move(krb5), std::make_unique<password_provider::PasswordProvider>(),
      metrics_.get());
  manager_->LoadAccounts();

  // Wait a little before calling StartObservingTickets. Apparently, signals
  // are not quite wired up properly at this point. If signals are emitted here,
  // they never reach Chrome, even if Chrome made sure it connected to the
  // signal.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindRepeating(&KerberosAdaptor::StartObservingTickets,
                          weak_ptr_factory_.GetWeakPtr()),
      kTicketExpiryCheckDelay);
}

ByteArray KerberosAdaptor::AddAccount(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  AddAccountRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  if (error == ERROR_NONE) {
    error =
        manager_->AddAccount(request.principal_name(), request.is_managed());
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  AddAccountResponse response;
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::RemoveAccount(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  RemoveAccountRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  RemoveAccountResponse response;
  if (error == ERROR_NONE) {
    error = manager_->RemoveAccount(request.principal_name());
    GetAccountsList(response.mutable_accounts());
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::ClearAccounts(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  ClearAccountsRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  ClearAccountsResponse response;
  if (error == ERROR_NONE) {
    std::unordered_set<std::string> keep_list(
        request.principal_names_to_ignore_size());
    for (int n = 0; n < request.principal_names_to_ignore_size(); ++n)
      keep_list.insert(request.principal_names_to_ignore(n));

    error = manager_->ClearAccounts(request.mode(), std::move(keep_list));
    GetAccountsList(response.mutable_accounts());
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::ListAccounts(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  ListAccountsRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  // Note: request is empty right now, but keeping it for future changes.
  std::vector<Account> accounts;
  ListAccountsResponse response;
  if (error == ERROR_NONE)
    GetAccountsList(response.mutable_accounts());

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::SetConfig(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  SetConfigRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  if (error == ERROR_NONE)
    error = manager_->SetConfig(request.principal_name(), request.krb5conf());

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  SetConfigResponse response;
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::ValidateConfig(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  ValidateConfigRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  ConfigErrorInfo error_info;
  if (error == ERROR_NONE) {
    error = manager_->ValidateConfig(request.krb5conf(), &error_info);
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  metrics_->ReportValidateConfigErrorCode(error_info.code());
  ValidateConfigResponse response;
  response.set_error(error);
  *response.mutable_error_info() = error_info;
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::AcquireKerberosTgt(
    const ByteArray& request_blob, const base::ScopedFD& password_fd) {
  PrintRequest(__FUNCTION__);
  AcquireKerberosTgtRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  std::optional<std::string> password;
  if (error == ERROR_NONE) {
    password = ReadPipeToString(password_fd.get());
    if (!password.has_value()) {
      LOG(ERROR) << "Failed to read password pipe";
      error = ERROR_LOCAL_IO;
    }
  }

  if (error == ERROR_NONE) {
    metrics_->StartAcquireTgtTimer();
    error = manager_->AcquireTgt(request.principal_name(), password.value(),
                                 request.remember_password(),
                                 request.use_login_password());
    metrics_->StopAcquireTgtTimerAndReport();
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  AcquireKerberosTgtResponse response;
  response.set_error(error);
  return SerializeProto(response);
}

ByteArray KerberosAdaptor::GetKerberosFiles(const ByteArray& request_blob) {
  PrintRequest(__FUNCTION__);
  GetKerberosFilesRequest request;
  ErrorType error = ParseProto(&request, request_blob);

  GetKerberosFilesResponse response;
  if (error == ERROR_NONE) {
    error = manager_->GetKerberosFiles(request.principal_name(),
                                       response.mutable_files());
  }

  PrintResult(__FUNCTION__, error);
  metrics_->ReportDBusCallResult(__FUNCTION__, error);
  response.set_error(error);
  return SerializeProto(response);
}

void KerberosAdaptor::set_storage_dir_for_testing(const base::FilePath& dir) {
  DCHECK(!manager_);
  storage_dir_for_testing_ = dir;
}

void KerberosAdaptor::set_krb5_for_testing(
    std::unique_ptr<Krb5Interface> krb5) {
  DCHECK(!manager_);
  krb5_for_testing_ = std::move(krb5);
}

void KerberosAdaptor::set_metrics_for_testing(
    std::unique_ptr<KerberosMetrics> metrics) {
  DCHECK(!manager_);
  metrics_ = std::move(metrics);
}

void KerberosAdaptor::StartObservingTickets() {
  manager_->StartObservingTickets();
}

void KerberosAdaptor::OnKerberosFilesChanged(
    const std::string& principal_name) {
  LOG(INFO) << "Firing signal KerberosFilesChanged";
  SendKerberosFilesChangedSignal(principal_name);
}

void KerberosAdaptor::OnKerberosTicketExpiring(
    const std::string& principal_name) {
  LOG(INFO) << "Firing signal KerberosTicketExpiring";
  SendKerberosTicketExpiringSignal(principal_name);
}

void KerberosAdaptor::GetAccountsList(RepeatedAccountField* repeated_accounts) {
  std::vector<Account> accounts = manager_->ListAccounts();
  for (const auto& account : accounts)
    *repeated_accounts->Add() = account;
}

}  // namespace kerberos
