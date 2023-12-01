// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SMBPROVIDER_HELPER_H_
#define SMBPROVIDER_SMBPROVIDER_HELPER_H_

#include <ostream>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <libsmbclient.h>

#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"

namespace dbus {

class FileDescriptor;

}  // namespace dbus

namespace smbprovider {

using PathParts = const std::vector<std::string>;

// Helper method that appends a |base_path| to a |relative_path|. Base path may
// or may not contain a trailing separator ('/'). If |relative_path| starts with
// a leading "/", it is stripped before being appended to |base_path|.
std::string AppendPath(const std::string& base_path,
                       const std::string& relative_path);

// Helper method to check whether an entry is self (".") or parent ("..").
bool IsSelfOrParentDir(const std::string& entry_name);

// Helper method to check if the entry is a file or directory.
bool IsFileOrDir(uint32_t smbc_type);

// Maps errno to ErrorType.
ErrorType GetErrorFromErrno(int32_t error_code);

// Maps errno to ErrorType. This is a copy function of GetErrorFromErrno with
// a change on mapping EINVAL to ERROR_NOT_FOUND.
ErrorType GetErrorFromErrnoForReadDir(int32_t error_code);

// Helper method to determine whether a stat struct represents a Directory.
bool IsDirectory(const struct stat& stat_info);

// Helper method to detemine whether a stat struct represents a File.
bool IsFile(const struct stat& stat_info);

// Helper method to check if the entry is an SMB share.
bool IsSmbShare(uint32_t smbc_type);

// Helper method to check if MS/DOS file attributes |file_attrs| correspond to a
// symlink.
bool IsSymlink(uint16_t file_attrs);

void LogAndSetError(const char* operation_name,
                    int32_t mount_id,
                    ErrorType error_received,
                    int32_t* error_code);

// Logs error for |operation_name|.
void LogOperationError(const char* operation_name,
                       int32_t mount_id,
                       ErrorType error_received);

// Logs error and sets |error_code|.
template <typename Proto>
void LogAndSetError(const Proto& options,
                    ErrorType error_received,
                    int32_t* error_code) {
  LogAndSetError(GetMethodName(options), GetMountId(options), error_received,
                 error_code);
}

void LogAndSetDBusParseError(const char* operation_name, int32_t* error_code);

template <typename Proto>
bool ParseOptionsProto(const ProtoBlob& blob,
                       Proto* options,
                       int32_t* error_code) {
  bool is_valid = options->ParseFromArray(blob.data(), blob.size()) &&
                  IsValidOptions(*options);
  if (!is_valid) {
    LogAndSetDBusParseError(GetMethodName(*options), error_code);
  }

  return is_valid;
}

// Helper method to get |DirectoryEntryProto| from a struct stat. Returns
// ERROR_OK on success and ERROR_FAILED otherwise.
int32_t GetDirectoryEntryProtoFromStat(const std::string& full_path,
                                       const struct stat& stat_info,
                                       ProtoBlob* proto_blob);

// Helper method to determine if the open file flags are valid. Valid flags
// include: O_RDONLY, O_RDWR, O_WRONLY.
bool IsValidOpenFileFlags(int32_t flags);

// Gets the correct permissions flag for |options|.
int32_t GetOpenFilePermissions(const bool writeable);

// Returns the components of a filepath as a vector<std::string>.
PathParts SplitPath(const std::string& full_path);

// Removes smb:// from url. |smb_url| must start with "smb://".
std::string RemoveURLScheme(const std::string& smb_url);

// Returns the file component of a path.|full_path| must be an SMB Url.
std::string GetFileName(const std::string& full_path);

// Returns a string representing the filepath to the directory above the file.
// |full_path| must be an SMB Url.
std::string GetDirPath(const std::string& full_path);

// Helper method to determine if the result from CreateDirectory should be
// processed as an error. |result| is the result of the call to CreateDirectory.
// If |ignore_existing| is true, EEXIST errors are ignored.
bool ShouldReportCreateDirError(int32_t result, bool ignore_existing);

// Output operator for logging and debugging.
std::ostream& operator<<(std::ostream& out, ErrorType error);

}  // namespace smbprovider

#endif  // SMBPROVIDER_SMBPROVIDER_HELPER_H_
