// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/smbprovider.h"

#include <algorithm>
#include <map>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <crypto/sha2.h>
#include <dbus/smbprovider/dbus-constants.h>

#include "smbprovider/constants.h"
#include "smbprovider/file_copy_progress.h"
#include "smbprovider/iterator/caching_iterator.h"
#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/iterator/post_depth_first_iterator.h"
#include "smbprovider/mount_manager.h"
#include "smbprovider/netbios_packet_parser.h"
#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/recursive_copy_progress.h"
#include "smbprovider/samba_interface.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {

bool GetShareEntries(const GetSharesOptionsProto& options,
                     ShareIterator iterator,
                     int32_t* error_code,
                     ProtoBlob* out_entries) {
  DCHECK(error_code);
  DCHECK(out_entries);

  DirectoryEntryListProto directory_entries;

  int32_t result = iterator.Init();
  while (result == 0) {
    if (iterator.IsDone()) {
      *error_code = static_cast<int32_t>(
          SerializeProtoToBlob(directory_entries, out_entries));
      return true;
    }
    AddDirectoryEntry(iterator.Get(), &directory_entries);
    result = iterator.Next();
  }

  // The while-loop is only exited if there is an error. A full successful
  // execution will return from inside the above while-loop.
  *error_code = GetErrorFromErrno(result);
  LogOperationError(GetMethodName(options), GetMountId(options),
                    static_cast<ErrorType>(*error_code));
  return false;
}

SmbProvider::SmbProvider(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
    std::unique_ptr<MountManager> mount_manager,
    std::unique_ptr<KerberosArtifactSynchronizer>
        kerberos_artifact_synchronizer,
    const base::FilePath& daemon_store_directory)
    : org::chromium::SmbProviderAdaptor(this),
      dbus_object_(std::move(dbus_object)),
      mount_manager_(std::move(mount_manager)),
      kerberos_artifact_synchronizer_(
          std::move(kerberos_artifact_synchronizer)) {}

void SmbProvider::RegisterAsync(
    AsyncEventSequencer::CompletionAction completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));
}

void SmbProvider::ReadShareEntries(const ProtoBlob& options_blob,
                                   int32_t* error_code,
                                   ProtoBlob* out_entries) {
  DCHECK(error_code);
  DCHECK(out_entries);
  out_entries->clear();

  std::string full_path;
  GetSharesOptionsProto options;
  if (ParseOptionsAndPath(options_blob, &options, &full_path, error_code)) {
    SambaInterface* samba_interface = GetSambaInterface(GetMountId(options));

    GetShareEntries(options, ShareIterator(full_path, samba_interface),
                    error_code, out_entries);
  }
}

void SmbProvider::GetShares(const ProtoBlob& options_blob,
                            int32_t* error_code,
                            ProtoBlob* shares) {
  DCHECK(error_code);
  DCHECK(shares);

  ReadShareEntries(options_blob, error_code, shares);
}

void SmbProvider::SetupKerberos(SetupKerberosCallback callback,
                                const std::string& account_identifier) {
  kerberos_artifact_synchronizer_->SetupKerberos(
      account_identifier,
      base::BindOnce(&SmbProvider::HandleSetupKerberosResponse,
                     base::Unretained(this), std::move(callback)));
}

void SmbProvider::HandleSetupKerberosResponse(SetupKerberosCallback callback,
                                              bool result) {
  callback->Return(result);
}

ProtoBlob SmbProvider::ParseNetBiosPacket(const std::vector<uint8_t>& packet,
                                          uint16_t transaction_id) {
  const std::vector<std::string> servers =
      netbios::ParsePacket(packet, transaction_id);

  const HostnamesProto hostnames_proto = BuildHostnamesProto(servers);
  std::vector<uint8_t> out_blob;
  if (SerializeProtoToBlob(hostnames_proto, &out_blob) != ERROR_OK) {
    return ProtoBlob();
  }
  return out_blob;
}

HostnamesProto SmbProvider::BuildHostnamesProto(
    const std::vector<std::string>& hostnames) const {
  HostnamesProto hostnames_proto;
  for (const auto& hostname : hostnames) {
    AddToHostnamesProto(hostname, &hostnames_proto);
  }
  return hostnames_proto;
}

SambaInterface* SmbProvider::GetSambaInterface(int32_t mount_id) const {
  SambaInterface* samba_interface;
  if (mount_id == kInternalMountId) {
    samba_interface = mount_manager_->GetSystemSambaInterface();
  } else {
    bool success =
        mount_manager_->GetSambaInterface(mount_id, &samba_interface);
    DCHECK(success);
  }

  DCHECK(samba_interface);
  return samba_interface;
}

template <typename Proto>
bool SmbProvider::GetFullPath(const Proto* options,
                              std::string* full_path) const {
  DCHECK(options);
  DCHECK(full_path);

  const int32_t mount_id = GetMountId(*options);
  const std::string entry_path = GetEntryPath(*options);

  bool success = mount_manager_->GetFullPath(mount_id, entry_path, full_path);
  if (!success) {
    LOG(ERROR) << GetMethodName(*options) << " requested unknown mount_id "
               << mount_id;
  }

  return success;
}

template <>
bool SmbProvider::GetFullPath(const GetSharesOptionsProto* options,
                              std::string* full_path) const {
  DCHECK(options);
  DCHECK(full_path);

  *full_path = GetEntryPath(*options);
  return true;
}

template <typename Proto>
bool SmbProvider::ParseOptionsAndPath(const ProtoBlob& blob,
                                      Proto* options,
                                      std::string* full_path,
                                      int32_t* error_code) {
  if (!ParseOptionsProto(blob, options, error_code)) {
    return false;
  }

  if (!GetFullPath(options, full_path)) {
    *error_code = static_cast<int32_t>(ERROR_NOT_FOUND);
    return false;
  }

  return true;
}

}  // namespace smbprovider
