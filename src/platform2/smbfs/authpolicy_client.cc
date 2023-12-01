// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/authpolicy_client.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <authpolicy/proto_bindings/active_directory_info.pb.h>
#include <dbus/authpolicy/dbus-constants.h>
#include <dbus/message.h>

namespace smbfs {
namespace {

authpolicy::ErrorType GetErrorFromReader(dbus::MessageReader* reader) {
  int32_t int_error;
  if (!reader->PopInt32(&int_error)) {
    DLOG(ERROR) << "AuthPolicyClient: Failed to get an error from the response";
    return authpolicy::ERROR_DBUS_FAILURE;
  }
  if (int_error < 0 || int_error >= authpolicy::ERROR_COUNT) {
    return authpolicy::ERROR_UNKNOWN;
  }
  return static_cast<authpolicy::ErrorType>(int_error);
}

authpolicy::ErrorType GetErrorAndProto(
    dbus::Response* response, google::protobuf::MessageLite* protobuf) {
  if (!response) {
    DLOG(ERROR) << "AuthPolicyClient: Failed to call to authpolicy";
    return authpolicy::ERROR_DBUS_FAILURE;
  }
  dbus::MessageReader reader(response);
  const authpolicy::ErrorType error = GetErrorFromReader(&reader);

  if (error != authpolicy::ERROR_NONE) {
    LOG(ERROR) << "AuthPolicyClient: Failed to get Kerberos files with error "
               << error;
    return error;
  }

  if (!reader.PopArrayOfBytesAsProto(protobuf)) {
    DLOG(ERROR) << "AuthPolicyClient: Failed to parse protobuf.";
    return authpolicy::ERROR_DBUS_FAILURE;
  }
  return authpolicy::ERROR_NONE;
}

}  // namespace

AuthPolicyClient::AuthPolicyClient(scoped_refptr<dbus::Bus> bus)
    : auth_policy_object_proxy_(bus->GetObjectProxy(
          authpolicy::kAuthPolicyServiceName,
          dbus::ObjectPath(authpolicy::kAuthPolicyServicePath))) {}

void AuthPolicyClient::GetUserKerberosFiles(
    const std::string& object_guid, GetUserKerberosFilesCallback callback) {
  dbus::MethodCall method_call(authpolicy::kAuthPolicyInterface,
                               authpolicy::kGetUserKerberosFilesMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(object_guid);
  auth_policy_object_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&AuthPolicyClient::HandleGetUserKeberosFiles,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void AuthPolicyClient::ConnectToKerberosFilesChangedSignal(
    dbus::ObjectProxy::SignalCallback signal_callback,
    dbus::ObjectProxy::OnConnectedCallback on_connected_callback) {
  auth_policy_object_proxy_->ConnectToSignal(
      authpolicy::kAuthPolicyInterface,
      authpolicy::kUserKerberosFilesChangedSignal, std::move(signal_callback),
      std::move(on_connected_callback));
}

void AuthPolicyClient::HandleGetUserKeberosFiles(
    GetUserKerberosFilesCallback callback, dbus::Response* response) {
  authpolicy::KerberosFiles files_proto;
  bool success =
      (GetErrorAndProto(response, &files_proto) == authpolicy::ERROR_NONE);
  if (success && (!files_proto.has_krb5cc() || !files_proto.has_krb5conf())) {
    LOG(ERROR) << "AuthPolicyClient: Kerberos files are empty.";
    success = false;
  }

  std::move(callback).Run(success, files_proto.krb5cc(),
                          files_proto.krb5conf());
}

}  // namespace smbfs
