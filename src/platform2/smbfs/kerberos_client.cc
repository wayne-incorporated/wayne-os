// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/kerberos_client.h"

#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>
#include <dbus/kerberos/dbus-constants.h>
#include <dbus/message.h>

namespace smbfs {

namespace {

kerberos::ErrorType GetErrorAndProto(
    dbus::Response* response,
    kerberos::GetKerberosFilesResponse* response_proto) {
  if (!response) {
    DLOG(ERROR) << "KerberosClient: Failed to call to kerberos.";
    return kerberos::ERROR_DBUS_FAILURE;
  }

  dbus::MessageReader reader(response);
  if (!reader.PopArrayOfBytesAsProto(response_proto)) {
    DLOG(ERROR) << "KerberosClient: Failed to parse protobuf.";
    return kerberos::ERROR_DBUS_FAILURE;
  }

  kerberos::ErrorType error_code = response_proto->error();
  if (error_code != kerberos::ERROR_NONE) {
    LOG(ERROR) << "KerberosClient: Failed to get Kerberos files with error "
               << error_code;
  }
  return error_code;
}

}  // namespace

KerberosClient::KerberosClient(scoped_refptr<dbus::Bus> bus)
    : kerberos_object_proxy_(bus->GetObjectProxy(
          kerberos::kKerberosServiceName,
          dbus::ObjectPath(kerberos::kKerberosServicePath))) {}

void KerberosClient::GetUserKerberosFiles(
    const std::string& principal_name, GetUserKerberosFilesCallback callback) {
  dbus::MethodCall method_call(kerberos::kKerberosInterface,
                               kerberos::kGetKerberosFilesMethod);
  dbus::MessageWriter writer(&method_call);
  kerberos::GetKerberosFilesRequest request;
  request.set_principal_name(principal_name);
  writer.AppendProtoAsArrayOfBytes(request);
  kerberos_object_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&KerberosClient::HandleGetUserKeberosFiles,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void KerberosClient::ConnectToKerberosFilesChangedSignal(
    dbus::ObjectProxy::SignalCallback signal_callback,
    dbus::ObjectProxy::OnConnectedCallback on_connected_callback) {
  kerberos_object_proxy_->ConnectToSignal(
      kerberos::kKerberosInterface, kerberos::kKerberosFilesChangedSignal,
      std::move(signal_callback), std::move(on_connected_callback));
}

void KerberosClient::HandleGetUserKeberosFiles(
    GetUserKerberosFilesCallback callback, dbus::Response* response) {
  kerberos::GetKerberosFilesResponse response_proto;
  bool success =
      (GetErrorAndProto(response, &response_proto) == kerberos::ERROR_NONE);
  if (success &&
      (!response_proto.has_files() || !response_proto.files().has_krb5cc() ||
       !response_proto.files().has_krb5conf())) {
    LOG(WARNING) << "KerberosClient: Kerberos files are empty.";
    success = false;
  }

  std::move(callback).Run(success, response_proto.files().krb5cc(),
                          response_proto.files().krb5conf());
}

}  // namespace smbfs
