// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/arcvm_data_migration_helper_delegate.h"

#include <errno.h>
#include <sys/stat.h>

#include <array>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_util.h>
#include <base/system/sys_info.h>

using cryptohome::data_migrator::FailureLocationType;

namespace arc::data_migrator {

// This should be kept in sync with |kPrefixRegexp| in
// arc/vm/data_migrator/logging.cc.
const char kDestinationMountPoint[] = "/tmp/arcvm-data-migration-mount";

namespace {

constexpr char kMtimeXattrName[] = "trusted.ArcVmDataMigrationMtime";
constexpr char kAtimeXattrName[] = "trusted.ArcVmDataMigrationAtime";

// Virtio-fs translates security.* xattrs in ARCVM to user.virtiofs.security.*
// on the host-side (b/155443663), so convert them back to security.* xattr in
// the migration.
constexpr char kVirtiofsSecurityXattrPrefix[] = "user.virtiofs.security.";
constexpr char kVirtiofsXattrPrefix[] = "user.virtiofs.";

static_assert(base::StringPiece(kVirtiofsSecurityXattrPrefix)
                  .find(kVirtiofsXattrPrefix) == 0);

// This must be a file path on the stateful partition, since both of the
// migration source and the destination are there when the destination is a
// crosvm disk image.
// TODO(b/280248293): Reconsider this path when we roll out the migration to
// LVM-enabled devices.
constexpr char kPathToCheckFreeDiskSpaceForMigrator[] = "/home";

// Struct to describe a single range of Android UID/GID mapping.
// 'T' is either uid_t or gid_t.
template <typename T>
struct IdMap {
  T guest;  // start of range on the guest side.
  T host;   // start of range on the host side.
  T size;   // size of the range of the mapping.
};

// UID mappings for Android's /data directory done by virtio-fs.
// Taken from platform2/vm_tools/concierge/vm_util.cc (originally from
// platform2/arc/container/bundle/pi/config.json).
constexpr std::array<IdMap<uid_t>, 3> kAndroidUidMap{{
    {0, 655360, 5000},
    {5000, 600, 50},
    {5050, 660410, 1994950},
}};

// GID equivalent of |kAndroidUidMap|.
constexpr std::array<IdMap<gid_t>, 5> kAndroidGidMap{{
    {0, 655360, 1065},
    {1065, 20119, 1},
    {1066, 656426, 3934},
    {5000, 600, 50},
    {5050, 660410, 1994950},
}};

template <typename T, size_t N>
std::optional<T> MapToGuestId(T host_id,
                              const std::array<IdMap<T>, N>& id_maps,
                              base::StringPiece id_name) {
  for (const auto& id_map : id_maps) {
    if (id_map.host <= host_id && host_id < id_map.host + id_map.size) {
      return host_id - id_map.host + id_map.guest;
    }
  }
  LOG(ERROR) << "Failed to translate host " << id_name << ": " << host_id;
  return std::nullopt;
}

// Struct for defining mappings from file paths and FailureLocationType to
// FailedPathType. Each member of this struct corresponds to each type in
// FailureLocationType.
struct PathTypes {
  FailedPathType type_source;
  FailedPathType type_dest;
  FailedPathType type_source_or_dest;
};

// Defines the mapping from file paths and FailureLocationType to
// FailedPathType. List subdirectories first to get longest match.
constexpr std::array<std::pair<const char*, PathTypes>, 7> kPathTypeMappings = {
    {
        {"app", PathTypes{FailedPathType::kAppSource, FailedPathType::kAppDest,
                          FailedPathType::kApp}},
        {"data", PathTypes{FailedPathType::kDataSource,
                           FailedPathType::kDataDest, FailedPathType::kData}},
        {"media/0/Android/data",
         PathTypes{FailedPathType::kMediaAndroidDataSource,
                   FailedPathType::kMediaAndroidDataDest,
                   FailedPathType::kMediaAndroidData}},
        {"media/0/Android/obb",
         PathTypes{FailedPathType::kMediaAndroidObbSource,
                   FailedPathType::kMediaAndroidObbDest,
                   FailedPathType::kMediaAndroidObb}},
        {"media/0",
         PathTypes{FailedPathType::kMediaSource, FailedPathType::kMediaDest,
                   FailedPathType::kMedia}},
        {"user/0", PathTypes{FailedPathType::kUserSource,
                             FailedPathType::kUserDest, FailedPathType::kUser}},
        {"user_de/0",
         PathTypes{FailedPathType::kUserDeSource, FailedPathType::kUserDeDest,
                   FailedPathType::kUserDe}},
    }};

}  // namespace

ArcVmDataMigrationHelperDelegate::ArcVmDataMigrationHelperDelegate(
    const base::FilePath& source, ArcVmDataMigratorMetrics* metrics)
    : source_(source), metrics_(metrics) {}

ArcVmDataMigrationHelperDelegate::~ArcVmDataMigrationHelperDelegate() = default;

bool ArcVmDataMigrationHelperDelegate::ShouldCopyQuotaProjectId() {
  return true;
}

std::string ArcVmDataMigrationHelperDelegate::GetMtimeXattrName() {
  return kMtimeXattrName;
}

std::string ArcVmDataMigrationHelperDelegate::GetAtimeXattrName() {
  return kAtimeXattrName;
}

bool ArcVmDataMigrationHelperDelegate::ConvertFileMetadata(
    base::stat_wrapper_t* stat) {
  std::optional<uid_t> guest_uid =
      MapToGuestId(stat->st_uid, kAndroidUidMap, "UID");
  std::optional<gid_t> guest_gid =
      MapToGuestId(stat->st_gid, kAndroidGidMap, "GID");
  if (!guest_uid.has_value() || !guest_gid.has_value()) {
    return false;
  }
  stat->st_uid = guest_uid.value();
  stat->st_gid = guest_gid.value();
  return true;
}

std::string ArcVmDataMigrationHelperDelegate::ConvertXattrName(
    const std::string& name) {
  if (base::StartsWith(name, kVirtiofsSecurityXattrPrefix)) {
    return name.substr(std::char_traits<char>::length(kVirtiofsXattrPrefix));
  }
  return name;
}

int64_t ArcVmDataMigrationHelperDelegate::FreeSpaceForMigrator() {
  return base::SysInfo::AmountOfFreeDiskSpace(
      base::FilePath(kPathToCheckFreeDiskSpaceForMigrator));
}

void ArcVmDataMigrationHelperDelegate::ReportStartTime() {
  migration_start_time_ = base::TimeTicks::Now();
}

void ArcVmDataMigrationHelperDelegate::ReportEndTime() {
  metrics_->ReportDuration(base::TimeTicks::Now() - migration_start_time_);
}

void ArcVmDataMigrationHelperDelegate::ReportStartStatus(
    cryptohome::data_migrator::MigrationStartStatus status) {
  metrics_->ReportStartStatus(status);
}

void ArcVmDataMigrationHelperDelegate::ReportEndStatus(
    cryptohome::data_migrator::MigrationEndStatus status) {
  metrics_->ReportEndStatus(status);
}

void ArcVmDataMigrationHelperDelegate::ReportTotalSize(int total_byte_count_mb,
                                                       int total_file_count) {
  metrics_->ReportTotalByteCountInMb(total_byte_count_mb);
  metrics_->ReportTotalFileCount(total_file_count);
}

void ArcVmDataMigrationHelperDelegate::ReportFailure(
    base::File::Error error_code,
    cryptohome::data_migrator::MigrationFailedOperationType type,
    const base::FilePath& path,
    FailureLocationType location_type) {
  if (error_code == base::File::FILE_ERROR_ACCESS_DENIED &&
      type == cryptohome::data_migrator::kMigrationFailedAtOpenSourceFile) {
    // Inspect and report the detailed cause of b/280247852.
    // Note that we assume that errno here indicates the cause of the failure
    // unless it is due to base::FilePath::ReferencesParent().
    metrics_->ReportAccessDeniedAtOpenSourceFileFailureType(
        GetAccessDeniedAtOpenFileFailureType(path, errno));
  }
  metrics_->ReportFailedErrorCode(error_code);
  metrics_->ReportFailedOperationType(type);
  metrics_->ReportFailedPathType(MapPathToPathType(path, location_type));
}

void ArcVmDataMigrationHelperDelegate::ReportFailedNoSpace(
    int initial_free_space_mb, int failure_free_space_mb) {
  metrics_->ReportInitialFreeSpace(initial_free_space_mb);
  metrics_->ReportNoSpaceFailureFreeSpace(failure_free_space_mb);
}

void ArcVmDataMigrationHelperDelegate::ReportFailedNoSpaceXattrSizeInBytes(
    int total_xattr_size_bytes) {
  metrics_->ReportNoSpaceXattrSize(total_xattr_size_bytes);
}

FailedPathType ArcVmDataMigrationHelperDelegate::MapPathToPathType(
    const base::FilePath& path, FailureLocationType location_type) {
  // Support absolute paths for |path| just in case, by converting them to
  // relative paths from the migration root.
  base::FilePath relative_path;
  if (path.IsAbsolute()) {
    if (!source_.AppendRelativePath(path, &relative_path) &&
        !base::FilePath(kDestinationMountPoint)
             .AppendRelativePath(path, &relative_path)) {
      LOG(WARNING) << "Cannot map an absolute path that is not under the "
                   << "migration source or the destination";
      return FailedPathType::kUnknownAbsolutePath;
    }
  } else {
    relative_path = path;
  }

  for (const auto& [directory, types] : kPathTypeMappings) {
    if (base::FilePath(directory).IsParent(relative_path)) {
      switch (location_type) {
        case FailureLocationType::kSource:
          return types.type_source;
        case FailureLocationType::kDest:
          return types.type_dest;
        case FailureLocationType::kSourceOrDest:
          return types.type_source_or_dest;
      }
    }
  }

  switch (location_type) {
    case FailureLocationType::kSource:
      return FailedPathType::kOtherSource;
    case FailureLocationType::kDest:
      return FailedPathType::kOtherDest;
    case FailureLocationType::kSourceOrDest:
      return FailedPathType::kOther;
  }
}

AccessDeniedAtOpenFileFailureType
ArcVmDataMigrationHelperDelegate::GetAccessDeniedAtOpenFileFailureType(
    const base::FilePath& path, int saved_errno) {
  if (path.ReferencesParent()) {
    const std::vector<std::string> components = path.GetComponents();
    for (const auto& component : components) {
      if (component == base::FilePath::kParentDirectory) {
        return AccessDeniedAtOpenFileFailureType::kReferencesParent;
      }
    }
    // There can be cases where base::FilePath::ReferencesParent() returns true
    // for valid (but unusual) file names like "...". See crbug/181617.
    return AccessDeniedAtOpenFileFailureType::kReferencesParentFalsePositive;
  }

  // Infer the cause based on errno. See base::File::OSErrorToFileError() for
  // values corresponding to base::FileError::FILE_ERROR_ACCESS_DENIED.
  switch (saved_errno) {
    case EACCES:
      return AccessDeniedAtOpenFileFailureType::kPermissionDenied;
    case EISDIR:
      return AccessDeniedAtOpenFileFailureType::kIsADirectory;
    case EROFS:
      return AccessDeniedAtOpenFileFailureType::kReadOnlyFileSystem;
    case EPERM:
      return AccessDeniedAtOpenFileFailureType::kOperationNotPermitted;
    default:
      LOG(WARNING) << "Unexpected errno for FILE_ERROR_ACCESS_DENIED: "
                   << base::safe_strerror(saved_errno) << " (" << saved_errno
                   << ")";
      return AccessDeniedAtOpenFileFailureType::kOther;
  }
}

}  // namespace arc::data_migrator
