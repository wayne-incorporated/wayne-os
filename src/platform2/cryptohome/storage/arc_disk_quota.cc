// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/arc_disk_quota.h"

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/cryptohome.h>

#include "cryptohome/projectid_config.h"

namespace cryptohome {

namespace {

bool IsAndroidProjectId(int project_id) {
  return (project_id >= kProjectIdForAndroidFilesStart &&
          project_id <= kProjectIdForAndroidFilesEnd) ||
         (project_id >= kProjectIdForAndroidAppsStart &&
          project_id <= kProjectIdForAndroidAppsEnd);
}

}  // namespace

ArcDiskQuota::ArcDiskQuota(HomeDirs* homedirs,
                           Platform* platform,
                           const base::FilePath& home)
    : homedirs_(homedirs), platform_(platform), home_(home) {}

ArcDiskQuota::~ArcDiskQuota() = default;

void ArcDiskQuota::Initialize() {
  device_ = GetDevice();
}

bool ArcDiskQuota::IsQuotaSupported() const {
  base::FilePath device = GetDevice();
  if (device.empty()) {
    LOG(ERROR) << "No quota mount is found.";
    return false;
  }

  int cnt = homedirs_->GetUnmountedAndroidDataCount();
  if (cnt != 0) {
    // Quota is not supported if there are one or more unmounted Android users.
    // (b/181159107)
    return false;
  }

  return true;
}

int64_t ArcDiskQuota::GetCurrentSpaceForUid(uid_t android_uid) const {
  base::FilePath device = GetDevice();
  if (android_uid < kAndroidUidStart || android_uid > kAndroidUidEnd) {
    LOG(ERROR) << "Android uid " << android_uid
               << " is outside the allowed query range";
    return -1;
  }
  if (device.empty()) {
    LOG(ERROR) << "No quota mount is found";
    return -1;
  }
  uid_t real_uid = android_uid + kArcContainerShiftUid;
  int64_t current_space =
      platform_->GetQuotaCurrentSpaceForUid(device, real_uid);
  if (current_space == -1) {
    PLOG(ERROR) << "Failed to get disk stats for uid: " << real_uid;
    return -1;
  }
  return current_space;
}

int64_t ArcDiskQuota::GetCurrentSpaceForGid(gid_t android_gid) const {
  base::FilePath device = GetDevice();
  if (android_gid < kAndroidGidStart || android_gid > kAndroidGidEnd) {
    LOG(ERROR) << "Android gid " << android_gid
               << " is outside the allowed query range";
    return -1;
  }
  if (device.empty()) {
    LOG(ERROR) << "No quota mount is found";
    return -1;
  }
  gid_t real_gid = android_gid + kArcContainerShiftGid;
  int64_t current_space =
      platform_->GetQuotaCurrentSpaceForGid(device, real_gid);
  if (current_space == -1) {
    PLOG(ERROR) << "Failed to get disk stats for gid: " << real_gid;
    return -1;
  }
  return current_space;
}

int64_t ArcDiskQuota::GetCurrentSpaceForProjectId(int project_id) const {
  base::FilePath device = GetDevice();
  if (!IsAndroidProjectId(project_id)) {
    LOG(ERROR) << "Project id " << project_id
               << " is outside the allowed query range";
    return -1;
  }
  if (device.empty()) {
    LOG(ERROR) << "No quota mount is found";
    return -1;
  }
  int64_t current_space =
      platform_->GetQuotaCurrentSpaceForProjectId(device, project_id);
  if (current_space == -1) {
    PLOG(ERROR) << "Failed to get disk stats for project id: " << project_id;
    return -1;
  }
  return current_space;
}

bool ArcDiskQuota::IsMediaRWDataFileContext(const std::string& context) {
  const auto context_tokens = base::SplitStringPiece(
      context, ":", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  if (context_tokens.size() < kMediaRWDataFileSELinuxContextTokens.size()) {
    return false;
  }
  // Check if the prefix of the context matches the expected SELinux context.
  if (!std::equal(kMediaRWDataFileSELinuxContextTokens.begin(),
                  kMediaRWDataFileSELinuxContextTokens.end(),
                  context_tokens.begin())) {
    return false;
  }

  // Everything matches.
  if (context_tokens.size() == kMediaRWDataFileSELinuxContextTokens.size()) {
    return true;
  }

  // Check if the suffix of the context is valid based on
  // external/selinux/libselinux/src/android/android_platform.c in the Android
  // repository.

  // The suffix should consists of exactly one extra token.
  if (context_tokens.size() !=
      kMediaRWDataFileSELinuxContextTokens.size() + 1) {
    return false;
  }
  const auto category_tokens = base::SplitStringPiece(
      context_tokens.back(), ",", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);

  std::vector<int> categories;
  for (const auto& token : category_tokens) {
    // Each token should contain at least two characters and in the form of c%u.
    if (token.length() < 2) {
      return false;
    }
    if (token[0] != 'c') {
      return false;
    }
    int category = -1;
    if (!base::StringToInt(token.substr(1), &category)) {
      return false;
    }
    categories.push_back(category);
  }

  // The checks below check if each category belongs to app id or user.
  // Since ARCVM only has user 0, when the category is user category, we only
  // do exact comparison: either with 512 + 0 or 768 + 0 (where 512 and 768 are
  // the constants that are defined in
  // external/selinux/libselinux/src/android/android_platform.c in the Android
  // repository).
  if (categories.size() == 2) {
    return ((0 <= categories[0] && categories[0] < 256 &&
             256 <= categories[1] && categories[1] < 512) ||
            (512 == categories[0] && categories[1] == 768));
  } else if (categories.size() == 4) {
    return (0 <= categories[0] && categories[0] < 256 && 256 <= categories[1] &&
            categories[1] < 512 && categories[2] == 512 &&
            categories[3] == 768);
  } else {
    // Known suffix consists of only two or four categories.
    return false;
  }
}

bool ArcDiskQuota::SetMediaRWDataFileProjectId(int project_id,
                                               int fd,
                                               int* out_error) const {
  if (!IsAndroidProjectId(project_id)) {
    LOG(ERROR) << "Project id " << project_id
               << " is outside the allowed query range";
    *out_error = EINVAL;
    return false;
  }
  std::optional<std::string> context = platform_->GetSELinuxContextOfFD(fd);
  if (!context) {
    LOG(ERROR) << "Failed to get the SELinux context of FD.";
    *out_error = EIO;
    return false;
  }
  if (!IsMediaRWDataFileContext(*context)) {
    LOG(ERROR) << "Unexpected SELinux context: " << *context;
    *out_error = EPERM;
    return false;
  }
  return platform_->SetQuotaProjectIdWithFd(project_id, fd, out_error);
}

bool ArcDiskQuota::SetMediaRWDataFileProjectInheritanceFlag(
    bool enable, int fd, int* out_error) const {
  std::optional<std::string> context = platform_->GetSELinuxContextOfFD(fd);
  if (!context) {
    LOG(ERROR) << "Failed to get the SELinux context of FD.";
    *out_error = EIO;
    return false;
  }
  if (!IsMediaRWDataFileContext(*context)) {
    LOG(ERROR) << "Unexpected SELinux context: " << *context;
    *out_error = EPERM;
    return false;
  }
  return platform_->SetQuotaProjectInheritanceFlagWithFd(enable, fd, out_error);
}

base::FilePath ArcDiskQuota::GetDevice() const {
  std::string device;
  if (!platform_->FindFilesystemDevice(home_, &device)) {
    LOG(ERROR) << "Home device is not found.";
    return base::FilePath();
  }

  // Check if the device is mounted with quota option.
  if (platform_->GetQuotaCurrentSpaceForUid(base::FilePath(device), 0) < 0) {
    LOG(ERROR) << "Device is not mounted with quota feature enabled.";
    return base::FilePath();
  }

  return base::FilePath(device);
}

}  // namespace cryptohome
