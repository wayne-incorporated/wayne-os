// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "image-burner/image_burner_impl.h"

#include <ctype.h>
#include <regex.h>
#include <stdint.h>

#include <memory>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/cryptohome.h>

namespace imageburn {

namespace {

const int kBurningBlockSize = 4 * 1024;  // 4 KiB

const char* kFilePathPatterns[] = {"^/dev/sd[a-z]+$", "^/dev/mmcblk[0-9]+$"};
const int kFilePathPatternCount = 2;

const char kMediaDirectory[] = "/media";
const char kUserRootDirectory[] = "/home/chronos";

bool IsUserOrUserHash(const std::string& path) {
  if (path == "user")
    return true;

  if (base::StartsWith(path, "u-", base::CompareCase::INSENSITIVE_ASCII) &&
      brillo::cryptohome::home::IsSanitizedUserName(path.substr(2))) {
    return true;
  }

  return false;
}

}  // namespace

BurnerImpl::BurnerImpl(FileSystemWriter* writer,
                       FileSystemReader* reader,
                       SignalSender* signal_sender,
                       PathGetter* path_getter)
    : writer_(writer),
      reader_(reader),
      signal_sender_(signal_sender),
      path_getter_(path_getter),
      data_block_size_(kBurningBlockSize) {}

ErrorCode BurnerImpl::BurnImage(const char* from_path, const char* to_path) {
  ErrorCode err = IMAGEBURN_OK;

  if (!writer_ || !reader_ || !signal_sender_ || !path_getter_)
    err = IMAGEBURN_ERROR_BURNER_NOT_INITIALIZED;

  if (!err)
    ValidateTargetPath(to_path, &err);

  std::string resolved_from_path;
  if (!err)
    ValidateSourcePath(from_path, &resolved_from_path, &err);

  if (!err)
    DoBurn(resolved_from_path.c_str(), to_path, &err);

  // TODO(tbarzic) send error specific error message.
  signal_sender_->SendFinishedSignal(to_path, !err,
                                     (!err ? "" : "Error during burn"));
  return err;
}

void BurnerImpl::InitSignalSender(SignalSender* signal_sender) {
  signal_sender_ = signal_sender;
}

bool BurnerImpl::ValidateTargetPath(const char* path, ErrorCode* error) {
  if (!path) {
    *error = IMAGEBURN_ERROR_NULL_TARGET_PATH;
    LOG(ERROR) << "Target path set to NULL.";
    return false;
  }

  // Check if path conforms to a valid regex.
  bool is_pattern_valid = false;
  for (int i = 0; i < kFilePathPatternCount; ++i) {
    regex_t re;
    int status = regcomp(&re, kFilePathPatterns[i], REG_EXTENDED);
    DCHECK_EQ(0, status);
    status = regexec(&re, path, 0, NULL, 0);
    regfree(&re);
    if (status == 0) {
      is_pattern_valid = true;
      break;
    }
  }

  if (!is_pattern_valid) {
    *error = IMAGEBURN_ERROR_INVALID_TARGET_PATH;
    LOG(ERROR) << "Target path does not have a valid file path pattern.";
    return false;
  }

  std::string root_path;
  // This will return roots file path, so we can compare target path, which
  // should also be devices file path, to it.
  bool got_root_path = path_getter_->GetRootPath(&root_path);
  if (!got_root_path ||
      strncmp(root_path.c_str(), path, root_path.length()) == 0) {
    *error = IMAGEBURN_ERROR_TARGET_PATH_ON_ROOT;
    LOG(ERROR) << "Target path is on root device.";
    return false;
  }

  return true;
}

bool BurnerImpl::ValidateSourcePath(const char* path,
                                    std::string* resolved_path,
                                    ErrorCode* error) {
  resolved_path->clear();
  if (!path) {
    *error = IMAGEBURN_ERROR_NULL_SOURCE_PATH;
    LOG(ERROR) << "Source path set to NULL.";
    return false;
  }

  if (!path_getter_->GetRealPath(path, resolved_path)) {
    *error = IMAGEBURN_ERROR_SOURCE_REAL_PATH_NOT_DETERMINED;
    return false;
  }

  if (!IsSourcePathAllowed(*resolved_path)) {
    *error = IMAGEBURN_ERROR_SOURCE_PATH_NOT_ALLOWED;
    LOG(ERROR) << "Source path is not from one of the allowed locations.";
    return false;
  }

  return true;
}

bool BurnerImpl::DoBurn(const char* from_path,
                        const char* to_path,
                        ErrorCode* error) {
  LOG(INFO) << "Burning " << from_path << " to " << to_path;
  *error = IMAGEBURN_OK;

  bool success = reader_->Open(from_path);
  if (success) {
    if (!(success = writer_->Open(to_path)))
      *error = IMAGEBURN_ERROR_CANNOT_OPEN_TARGET;
  } else {
    *error = IMAGEBURN_ERROR_CANNOT_OPEN_SOURCE;
  }

  if (success) {
    std::unique_ptr<char[]> buffer(new char[data_block_size_]);

    int64_t total_burnt = 0;
    int64_t image_size = reader_->GetSize();

    int len = 0;
    while ((len = reader_->Read(buffer.get(), data_block_size_)) > 0) {
      if (writer_->Write(buffer.get(), len) == len) {
        total_burnt += static_cast<int64_t>(len);
        signal_sender_->SendProgressSignal(total_burnt, image_size, to_path);
      } else {
        success = false;
        *error = IMAGEBURN_ERROR_FAILED_WRITING_TO_TARGET;
        break;
      }
    }
    if (len < 0) {
      success = false;
      *error = IMAGEBURN_ERROR_FAILED_READING_SOURCE;
    }
  }

  if (!writer_->Close() && success) {
    // We set this only when there is no previous error.
    success = false;
    *error = IMAGEBURN_ERROR_CANNOT_CLOSE_TARGET;
  }

  if (!reader_->Close() && success) {
    // We set this only when there is no previous error.
    success = false;
    *error = IMAGEBURN_ERROR_CANNOT_CLOSE_SOURCE;
  }
  return success;
}

// Derived from cros-disks::ArchiveManager::CanMount().
bool BurnerImpl::IsSourcePathAllowed(const std::string& source_path) const {
  // TODO(benchan): Revisit the need to allow .../Downloads once the MyFiles
  // migration (chromium:873539) is complete.
  //
  // The following paths are allowed:
  //     /home/chronos/user/Downloads/...<file>
  //     /home/chronos/user/MyFiles/...<file>
  //     /home/chronos/user/GCache/...<file>
  //     /home/chronos/u-<user-id>/Downloads/...<file>
  //     /home/chronos/u-<user-id>/MyFiles/...<file>
  //     /home/chronos/u-<user-id>/GCache/...<file>
  //     /media/<dir>/<dir>/...<file>
  //
  base::FilePath file_path(source_path);
  if (base::FilePath(kUserRootDirectory).IsParent(file_path)) {
    std::vector<std::string> components =
        file_path.StripTrailingSeparators().GetComponents();
    // The file path of an image file under a user's Downloads, MyFiles or
    // GCache directory path is split into the following components:
    //   '/', 'home', 'chronos', 'user', 'Downloads', ..., <file>
    //   '/', 'home', 'chronos', 'user', 'MyFiles', ..., <file>
    //   '/', 'home', 'chronos', 'user', 'GCache', ..., <file>
    //   '/', 'home', 'chronos', 'u-<userid>', 'Downloads', ..., <file>
    //   '/', 'home', 'chronos', 'u-<userid>', 'MyFiles', ..., <file>
    //   '/', 'home', 'chronos', 'u-<userid>', 'GCache', ..., <file>
    if (components.size() > 5 && IsUserOrUserHash(components[3]) &&
        (components[4] == "Downloads" || components[4] == "MyFiles" ||
         components[4] == "GCache")) {
      return true;
    }
  }

  if (base::FilePath(kMediaDirectory).IsParent(file_path)) {
    std::vector<std::string> components =
        file_path.StripTrailingSeparators().GetComponents();
    // A mount directory is always created under /media/<sub type>/<mount dir>,
    // so the file path of an image file under a mount directory is split
    // into more than 4 components:
    //   '/', 'media', 'removable', 'usb', ..., <file>
    if (components.size() > 4)
      return true;
  }
  return false;
}

}  // namespace imageburn
