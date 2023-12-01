// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_PROTO_H_
#define SMBPROVIDER_PROTO_H_

#include <string>
#include <vector>

#include "smbprovider/mount_config.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"

#include <base/check.h>

namespace smbprovider {

// Used as buffer for serialized protobufs.
using ProtoBlob = std::vector<uint8_t>;

// Serializes |proto| to the byte array |proto_blob|. Returns ERROR_OK on
// success and ERROR_FAILED on failure.
ErrorType SerializeProtoToBlob(const google::protobuf::MessageLite& proto,
                               ProtoBlob* proto_blob);

// Helper method to check whether a Proto has valid fields.
bool IsValidOptions(const GetSharesOptionsProto& options);

// Helper method to get the entry path from a proto.
std::string GetEntryPath(const GetSharesOptionsProto& options);

// Helper method to get the corresponding method name for each proto.
const char* GetMethodName(const GetSharesOptionsProto& unused);

template <typename Proto>
int32_t GetMountId(const Proto& options) {
  return options.mount_id();
}

template <>
int32_t GetMountId(const GetSharesOptionsProto& unused);

// Struct mapping to DirectoryEntryProto.
struct DirectoryEntry {
  bool is_directory;
  std::string name;
  std::string full_path;
  int64_t size;
  int64_t last_modified_time;

  DirectoryEntry() = default;

  DirectoryEntry(bool is_directory,
                 const std::string& name,
                 const std::string& full_path,
                 int64_t size,
                 int64_t last_modified_time)
      : is_directory(is_directory),
        name(name),
        full_path(full_path),
        size(size),
        last_modified_time(last_modified_time) {}

  DirectoryEntry(bool is_directory,
                 const std::string& name,
                 const std::string& full_path)
      : DirectoryEntry(is_directory,
                       name,
                       full_path,
                       -1 /* size */,
                       -1 /* last_modified_time */) {}
};

// Converts a vector of DirectoryEnts into a DirectoryEntryListProto.
void SerializeDirEntryVectorToProto(
    const std::vector<DirectoryEntry>& entries_vector,
    DirectoryEntryListProto* entries_proto);

void AddDirectoryEntry(const DirectoryEntry& entry,
                       DirectoryEntryListProto* proto);

void ConvertToProto(const DirectoryEntry& entry, DirectoryEntryProto* proto);

void AddToHostnamesProto(const std::string& hostname, HostnamesProto* proto);

}  // namespace smbprovider

#endif  // SMBPROVIDER_PROTO_H_
