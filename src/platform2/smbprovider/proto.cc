// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/proto.h"

#include <base/check.h>
#include <base/logging.h>
#include <dbus/smbprovider/dbus-constants.h>

#include "smbprovider/constants.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"

namespace smbprovider {

ErrorType SerializeProtoToBlob(const google::protobuf::MessageLite& proto,
                               ProtoBlob* proto_blob) {
  DCHECK(proto_blob);
  proto_blob->resize(proto.ByteSizeLong());
  bool success =
      proto.SerializeToArray(proto_blob->data(), proto.ByteSizeLong());
  if (!success) {
    LOG(ERROR) << "Unable to serialise proto " << proto.GetTypeName()
               << " size " << proto.GetCachedSize();
  }
  return success ? ERROR_OK : ERROR_FAILED;
}

bool IsValidOptions(const GetSharesOptionsProto& options) {
  return options.has_server_url();
}

std::string GetEntryPath(const GetSharesOptionsProto& options) {
  return options.server_url();
}

const char* GetMethodName(const GetSharesOptionsProto& unused) {
  return kGetSharesMethod;
}

template <>
int32_t GetMountId(const GetSharesOptionsProto& unused) {
  return kInternalMountId;
}

void SerializeDirEntryVectorToProto(
    const std::vector<DirectoryEntry>& entries_vector,
    DirectoryEntryListProto* entries_proto) {
  for (const auto& e : entries_vector) {
    AddDirectoryEntry(e, entries_proto);
  }
}

void AddDirectoryEntry(const DirectoryEntry& entry,
                       DirectoryEntryListProto* proto) {
  DCHECK(proto);
  DirectoryEntryProto* new_entry_proto = proto->add_entries();
  ConvertToProto(entry, new_entry_proto);
}

void ConvertToProto(const DirectoryEntry& entry, DirectoryEntryProto* proto) {
  DCHECK(proto);
  proto->set_is_directory(entry.is_directory);
  proto->set_name(entry.name);
  proto->set_size(entry.size);
  proto->set_last_modified_time(entry.last_modified_time);
}

void AddToHostnamesProto(const std::string& hostname, HostnamesProto* proto) {
  DCHECK(proto);
  proto->add_hostnames(hostname);
}

}  // namespace smbprovider
