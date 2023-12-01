// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/kerberos_client.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <dbus/kerberos/dbus-constants.h>
#include <dbus/message.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

namespace system_proxy {

namespace {
// The kerberos files are written in the mount namespace of the System-proxy
// daemon.
constexpr char kKrb5ConfFile[] = "/tmp/krb5.conf";
constexpr char kCCacheFile[] = "/tmp/ccache";

// Additional kerberos canonicalization settings and default realm. kerberosd
// doesn't set a default_realm. Chrome doesn't need it as it specifies the
// principal name when invoking gssapi methods.
constexpr char kKrb5Settings[] =
    "[libdefaults]\n"
    "\tdns_canonicalize_hostname = false\n"
    "\trdns = false\n"
    "\tdefault_realm = %s\n";

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
    : krb5_conf_path_(kKrb5ConfFile),
      krb5_ccache_path_(kCCacheFile),
      kerberos_object_proxy_(bus->GetObjectProxy(
          kerberos::kKerberosServiceName,
          dbus::ObjectPath(kerberos::kKerberosServicePath))) {
  kerberos_object_proxy_->WaitForServiceToBeAvailable(
      base::BindOnce(&KerberosClient::OnKerberosServiceAvailable,
                     weak_ptr_factory_.GetWeakPtr()));
}

void KerberosClient::SetPrincipalName(const std::string& principal_name) {
  DCHECK(kerberos_enabled_);
  principal_name_ = principal_name;
  if (principal_name_.empty()) {
    DeleteFiles();
    return;
  }
  GetFiles();
}

void KerberosClient::SetKerberosEnabled(bool enabled) {
  kerberos_enabled_ = enabled;
  if (kerberos_enabled_) {
    return;
  }
  principal_name_ = std::string();
  // Delete the krb ticket.
  DeleteFiles();
}

std::string KerberosClient::krb5_ccache_path() {
  return krb5_ccache_path_.MaybeAsASCII();
}
std::string KerberosClient::krb5_conf_path() {
  return krb5_conf_path_.MaybeAsASCII();
}

void KerberosClient::GetFiles() {
  if (principal_name_.empty() || !kerberos_enabled_) {
    return;
  }

  LOG(INFO) << "Request kerberos files from kerberosd.";
  dbus::MethodCall method_call(kerberos::kKerberosInterface,
                               kerberos::kGetKerberosFilesMethod);
  dbus::MessageWriter writer(&method_call);
  kerberos::GetKerberosFilesRequest request;
  request.set_principal_name(principal_name_);
  writer.AppendProtoAsArrayOfBytes(request);

  kerberos_object_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
      base::BindOnce(&KerberosClient::OnGetFilesResponse,
                     weak_ptr_factory_.GetWeakPtr()));
}

void KerberosClient::OnGetFilesResponse(dbus::Response* response) {
  kerberos::GetKerberosFilesResponse response_proto;
  bool success =
      (GetErrorAndProto(response, &response_proto) == kerberos::ERROR_NONE);
  if (success &&
      (!response_proto.has_files() || !response_proto.files().has_krb5cc() ||
       !response_proto.files().has_krb5conf())) {
    LOG(WARNING) << "KerberosClient: Kerberos files are empty.";
    success = false;
  }

  WriteFiles(response_proto.files().krb5cc(),
             UpdateKrbConfig(response_proto.files().krb5conf()));
}

void KerberosClient::WriteFiles(const std::string& krb5_ccache_data,
                                const std::string& krb5_conf_data) {
  bool success = !krb5_ccache_data.empty() && !krb5_conf_data.empty() &&
                 WriteFile(krb5_conf_path_, krb5_conf_data) &&
                 WriteFile(krb5_ccache_path_, krb5_ccache_data);
  if (!success)
    LOG(ERROR) << "Error retrieving the tickets";
}

void KerberosClient::ConnectToKerberosFilesChangedSignal() {
  kerberos_object_proxy_->ConnectToSignal(
      kerberos::kKerberosInterface, kerberos::kKerberosFilesChangedSignal,
      base::BindRepeating(&KerberosClient::OnKerberosFilesChanged,
                          base::Unretained(this)),
      base::BindOnce(&KerberosClient::OnKerberosFilesChangedSignalConnected,
                     base::Unretained(this)));
}

void KerberosClient::OnKerberosFilesChanged(dbus::Signal* signal) {
  DCHECK(signal);
  GetFiles();
}

void KerberosClient::OnKerberosFilesChangedSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  DCHECK(success);
  DCHECK_EQ(interface_name, kerberos::kKerberosInterface);
}

void KerberosClient::OnKerberosServiceAvailable(bool is_available) {
  if (!is_available) {
    LOG(ERROR) << "Kerberos service is not available";
    return;
  }
  ConnectToKerberosFilesChangedSignal();
}

bool KerberosClient::WriteFile(const base::FilePath& path,
                               const std::string& blob) {
  if (base::WriteFile(path, blob.c_str(), blob.size()) != blob.size()) {
    LOG(ERROR) << "Failed to write file " << path.value();
    return false;
  }
  return true;
}

void KerberosClient::DeleteFiles() {
  if (base::PathExists(krb5_conf_path_)) {
    if (!base::DeleteFile(krb5_conf_path_)) {
      PLOG(ERROR) << "Failed to clean up the kerberos config file";
    }
  }
  if (base::PathExists(krb5_ccache_path_)) {
    if (!base::DeleteFile(krb5_ccache_path_)) {
      PLOG(ERROR) << "Failed to clean up the kerberos tickets cache";
    }
  }
}

std::string KerberosClient::UpdateKrbConfig(const std::string& config_content) {
  if (config_content.empty() || principal_name_.empty()) {
    return config_content;
  }

  int pos = principal_name_.find("@");
  if (pos == std::string::npos) {
    LOG(ERROR) << "Invalid principal name";
    return config_content;
  }
  std::string realm = principal_name_.substr(pos + 1);
  std::string adjusted_config =
      base::StringPrintf(kKrb5Settings, realm.c_str());
  adjusted_config.append(config_content);

  return adjusted_config;
}

}  // namespace system_proxy
