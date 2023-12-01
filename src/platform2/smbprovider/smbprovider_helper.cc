// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/smbprovider_helper.h"

#include <errno.h>
#include <string.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <libsmbclient.h>

#include "smbprovider/constants.h"
#include "smbprovider/proto.h"

namespace smbprovider {

std::string AppendPath(const std::string& base_path,
                       const std::string& relative_path) {
  const base::FilePath path(base_path);
  base::FilePath relative(relative_path);
  if (relative.IsAbsolute() && relative_path.size() > 0) {
    // Remove the beginning "/" since FilePath#Append() cannot append an
    // 'absolute' path.
    relative = base::FilePath(
        base::StringPiece(relative_path.c_str() + 1, relative_path.size() - 1));
  }
  return path.Append(relative).value();
}

bool IsSelfOrParentDir(const std::string& entry_name) {
  return entry_name == kEntrySelf || entry_name == kEntryParent;
}

bool IsFileOrDir(uint32_t smbc_type) {
  return smbc_type == SMBC_FILE || smbc_type == SMBC_DIR;
}

bool IsSmbShare(uint32_t smbc_type) {
  return smbc_type == SMBC_FILE_SHARE;
}

bool IsSymlink(uint16_t file_attrs) {
  return file_attrs & kFileAttributeReparsePoint;
}

ErrorType GetErrorFromErrno(int32_t error_code) {
  DCHECK_GT(error_code, 0);
  switch (error_code) {
    case EPERM:
    case EACCES:
      return ERROR_ACCESS_DENIED;
    case ENOENT:
      return ERROR_NOT_FOUND;
    case EMFILE:
    case ENFILE:
      return ERROR_TOO_MANY_OPENED;
    case ENOTDIR:
      return ERROR_NOT_A_DIRECTORY;
    case EISDIR:
      return ERROR_NOT_A_FILE;
    case ENOTEMPTY:
      return ERROR_NOT_EMPTY;
    case EEXIST:
      return ERROR_EXISTS;
    case EINVAL:
      return ERROR_INVALID_OPERATION;
    case ECONNABORTED:
      return ERROR_SMB1_UNSUPPORTED;
    case EBADF:
    case ENODEV:
    case ETIMEDOUT:
      return ERROR_OPERATION_FAILED;
    default:
      LOG(WARNING) << "Unexpected error code " << error_code << ": "
                   << strerror(error_code);
      return ERROR_FAILED;
  }
}

// EINVAL is returned when Samba is unable to parse a hostname
// (eg. \\qnap\testshare). This problem is rooted in Samba, a proper fix would
// be to patch the Samba library.
ErrorType GetErrorFromErrnoForReadDir(int32_t error_code) {
  if (error_code == EINVAL) {
    return ERROR_NOT_FOUND;
  }

  return GetErrorFromErrno(error_code);
}

bool IsDirectory(const struct stat& stat_info) {
  return S_ISDIR(stat_info.st_mode);
}

bool IsFile(const struct stat& stat_info) {
  return S_ISREG(stat_info.st_mode);
}

void LogAndSetError(const char* operation_name,
                    int32_t mount_id,
                    ErrorType error_received,
                    int32_t* error_code) {
  LogOperationError(operation_name, mount_id, error_received);
  *error_code = static_cast<int32_t>(error_received);
}

void LogOperationError(const char* operation_name,
                       int32_t mount_id,
                       ErrorType error_received) {
  LOG(ERROR) << "Cannot " << operation_name << " on Mount [" << mount_id
             << "]: " << error_received;
}

void LogAndSetDBusParseError(const char* operation_name, int32_t* error_code) {
  LogAndSetError(operation_name, -1, ERROR_DBUS_PARSE_FAILED, error_code);
}

int32_t GetDirectoryEntryProtoFromStat(const std::string& full_path,
                                       const struct stat& stat_info,
                                       ProtoBlob* proto_blob) {
  DCHECK(proto_blob);
  bool is_directory = IsDirectory(stat_info);
  int64_t size = is_directory ? 0 : stat_info.st_size;
  const base::FilePath path(full_path);

  DirectoryEntryProto entry;
  entry.set_is_directory(is_directory);
  entry.set_name(path.BaseName().value());
  entry.set_size(size);
  entry.set_last_modified_time(stat_info.st_mtime);
  return static_cast<int32_t>(SerializeProtoToBlob(entry, proto_blob));
}

bool IsValidOpenFileFlags(int32_t flags) {
  return flags == O_RDONLY || flags == O_RDWR || flags == O_WRONLY;
}

int32_t GetOpenFilePermissions(const bool writeable) {
  return writeable ? O_RDWR : O_RDONLY;
}

PathParts SplitPath(const std::string& full_path) {
  DCHECK(!full_path.empty());
  base::FilePath path(full_path);
  std::vector<std::string> result = path.GetComponents();
  return result;
}

std::string RemoveURLScheme(const std::string& smb_url) {
  DCHECK_EQ(0, smb_url.compare(0, 6, kSmbUrlScheme));
  return smb_url.substr(5, std::string::npos);
}

std::string GetFileName(const std::string& full_path) {
  base::FilePath file_path(RemoveURLScheme(full_path));
  return file_path.BaseName().value();
}

std::string GetDirPath(const std::string& full_path) {
  std::string path = RemoveURLScheme(full_path);
  return base::FilePath(path).DirName().value();
}

bool ShouldReportCreateDirError(int32_t result, bool ignore_existing) {
  if (result == 0) {
    return false;
  }
  return !(result == EEXIST && ignore_existing);
}

std::ostream& operator<<(std::ostream& out, const ErrorType error) {
  switch (error) {
    case ERROR_NONE:
      return out << "ERROR_NONE";
    case ERROR_OK:
      return out << "ERROR_OK";
    case ERROR_FAILED:
      return out << "ERROR_FAILED";
    case ERROR_IN_USE:
      return out << "ERROR_IN_USE";
    case ERROR_EXISTS:
      return out << "ERROR_EXISTS";
    case ERROR_NOT_FOUND:
      return out << "ERROR_NOT_FOUND";
    case ERROR_ACCESS_DENIED:
      return out << "ERROR_ACCESS_DENIED";
    case ERROR_TOO_MANY_OPENED:
      return out << "ERROR_TOO_MANY_OPENED";
    case ERROR_NO_MEMORY:
      return out << "ERROR_NO_MEMORY";
    case ERROR_NO_SPACE:
      return out << "ERROR_NO_SPACE";
    case ERROR_NOT_A_DIRECTORY:
      return out << "ERROR_NOT_A_DIRECTORY";
    case ERROR_INVALID_OPERATION:
      return out << "ERROR_INVALID_OPERATION";
    case ERROR_SECURITY:
      return out << "ERROR_SECURITY";
    case ERROR_ABORT:
      return out << "ERROR_ABORT";
    case ERROR_NOT_A_FILE:
      return out << "ERROR_NOT_A_FILE";
    case ERROR_NOT_EMPTY:
      return out << "ERROR_NOT_EMPTY";
    case ERROR_INVALID_URL:
      return out << "ERROR_INVALID_URL";
    case ERROR_IO:
      return out << "ERROR_IO";
    case ERROR_PROVIDER_ERROR_COUNT:
      return out << "ERROR_PROVIDER_ERROR_COUNT";
    case ERROR_DBUS_PARSE_FAILED:
      return out << "ERROR_DBUS_PARSE_FAILED";
    case ERROR_COPY_PENDING:
      return out << "ERROR_COPY_PENDING";
    case ERROR_COPY_FAILED:
      return out << "ERROR_COPY_FAILED";
    case ERROR_SMB1_UNSUPPORTED:
      return out << "ERROR_SMB1_UNSUPPORTED";
    case ERROR_OPERATION_PENDING:
      return out << "ERROR_OPERATION_PENDING";
    case ERROR_OPERATION_FAILED:
      return out << "ERROR_OPERATION_FAILED";
    default:
      return out << "ERROR_"
                 << static_cast<std::underlying_type_t<ErrorType>>(error);
  }
}

}  // namespace smbprovider
