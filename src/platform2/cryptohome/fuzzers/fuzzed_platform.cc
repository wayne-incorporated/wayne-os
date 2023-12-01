// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fuzzers/fuzzed_platform.h"

#include <linux/fs.h>
#include <memory.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/sequence_checker.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/unguessable_token.h>
#include <brillo/process/process.h>
#include <brillo/process/process_mock.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>
#include <libhwsec-foundation/fuzzers/blob_mutator.h>
#include <libhwsec-foundation/fuzzers/fuzzed_proto_generator.h>

#include "cryptohome/dircrypto_util.h"
#include "cryptohome/platform.h"

namespace cryptohome {

using ::brillo::Blob;
using ::brillo::BlobFromString;
using ::brillo::BlobToString;
using ::brillo::SecureBlob;
using ::hwsec_foundation::FuzzedProtoGenerator;
using ::hwsec_foundation::MutateBlob;

namespace {

// Default file attributes used for virtual FS. They mimic typical conditions
// (for code running under root).
constexpr int kDefaultUserId = 0;
constexpr int kDefaultGroupId = 0;
constexpr mode_t kDefaultDirPermissions = 0755;
constexpr mode_t kDefaultFilePermissions = 0644;

// Semi-arbitrary parameters for blob mutation (e.g., applied to virtual FS
// contents):
// * How many times the mutated blob can be bigger than the original one:
constexpr size_t kBlobMutationSizeFactor = 2;
// * Upper boundary for the mutated blob size (used only if the original blob is
//   smaller):
constexpr size_t kBlobMutationDefaultMaxSize = 100;

// Used for interpreting the input supplied by the fuzzing framework as an
// instruction for how to build a fuzzed result in a piece of logic.
enum class FuzzResultStrategy {
  // The implementation should simulate the behavior as close to the "real"
  // platform as possible. E.g., file read operation should return contents from
  // the virtual FS.
  // NOTE: It's important this enum item comes first, because this speeds up the
  // fuzzer in discovering the "typical" scenario for code-under-test (this enum
  // is easy to pick by adding zeroes into the input or simply by making it too
  // short).
  kSimulate,
  // The implementation should return success (and fill output parameters, if
  // there are any, with "random" data).
  kPretendSuccess,
  // The implementation should return failure.
  kPretendFailure,

  // Must be the last item.
  kMaxValue = kPretendFailure
};

void AssertIsValidAbsolutePath(const base::FilePath& path) {
  CHECK(path.IsAbsolute()) << "path=" << path;
  // We make an assumption that code that uses `Platform` shouldn't pass paths
  // with ".." as it might indicate a security issue.
  CHECK(!path.ReferencesParent()) << "path=" << path;
}

// Removes extraneous characters from the path. E.g., "./b" is transformed into
// "b", "a//b/" into "a/b". The input path must not contain "..".
base::FilePath CanonicalizePath(const base::FilePath& path) {
  const std::vector<std::string> components = path.GetComponents();
  if (components.empty()) {
    return base::FilePath();
  }
  base::FilePath joined;
  for (const auto& component : components) {
    CHECK_NE(component, base::FilePath::kParentDirectory);
    if (component == base::FilePath::kCurrentDirectory) {
      continue;
    }
    if (joined.empty()) {
      joined = base::FilePath(component);
    } else {
      joined = joined.Append(component);
    }
  }
  return joined;
}

bool IsPathDescendant(const base::FilePath& candidate,
                      const base::FilePath& ancestor,
                      bool recursive) {
  if (!ancestor.IsParent(candidate)) {
    return false;
  }
  if (!recursive && candidate.DirName() != ancestor) {
    return false;
  }
  return true;
}

base::FilePath GenerateArbitraryDescendant(
    const base::FilePath& ancestor,
    bool recursive,
    FuzzedDataProvider& fuzzed_data_provider) {
  // Maximum size of a path to append to ancestor. We don't use unbounded random
  // strings because sometimes those can be very large and FilePath operations
  // (e.g. GetComponents) can scale very poorly with paths. Using double the max
  // path size should make sure actual large paths get generated while still
  // enforcing a cap on the size that FilePath will need to handle.
  static constexpr size_t kMaxSize = 2 * PATH_MAX;
  // Fallback path to use if for some reason the fuzzed path isn't usable.
  static constexpr char kFallbackPath[] = "foo";
  base::FilePath to_append(
      fuzzed_data_provider.ConsumeRandomLengthString(kMaxSize));
  if (to_append.value().empty() || to_append.IsAbsolute() ||
      to_append.ReferencesParent() ||
      to_append != CanonicalizePath(to_append) ||
      (!recursive && to_append.GetComponents().size() > 1)) {
    // If the random value doesn't satisfy conditions, use a stub value.
    to_append = base::FilePath(kFallbackPath);
  }
  return ancestor.Append(to_append);
}

base::stat_wrapper_t GetStat(const FuzzedPlatform::VirtualFsEntry& entry) {
  constexpr dev_t kStubDev = 123;
  constexpr ino64_t kStubIno = 456;
  constexpr dev_t kStubRdev = 789;
  constexpr time_t kStubAtime = 333;
  constexpr time_t kStubMtime = 222;
  constexpr time_t kStubCtime = 111;
  constexpr blksize_t kStubBlksize = 512;
  constexpr off64_t kStubSizeOfBlock = 512;
  base::stat_wrapper_t stat = {};
  stat.st_dev = kStubDev;
  stat.st_ino = kStubIno;
  stat.st_mode = (entry.is_dir ? S_IFDIR : S_IFREG) | entry.permissions;
  stat.st_nlink = 0;
  stat.st_uid = entry.user_id;
  stat.st_gid = entry.group_id;
  stat.st_rdev = kStubRdev;
  stat.st_size = entry.file_contents.size();
  stat.st_atime = kStubAtime;
  stat.st_mtime = kStubMtime;
  stat.st_ctime = kStubCtime;
  stat.st_blksize = kStubBlksize;
  stat.st_blocks =
      (entry.file_contents.size() + kStubSizeOfBlock - 1) / kStubSizeOfBlock;
  return stat;
}

base::stat_wrapper_t GenerateArbitraryStat(
    FuzzedDataProvider& fuzzed_data_provider) {
  base::stat_wrapper_t stat = {};
  stat.st_dev = fuzzed_data_provider.ConsumeIntegral<dev_t>();
  stat.st_ino = fuzzed_data_provider.ConsumeIntegral<ino64_t>();
  stat.st_mode = fuzzed_data_provider.ConsumeIntegral<mode_t>();
  stat.st_nlink = fuzzed_data_provider.ConsumeIntegral<nlink_t>();
  stat.st_uid = fuzzed_data_provider.ConsumeIntegral<uid_t>();
  stat.st_gid = fuzzed_data_provider.ConsumeIntegral<gid_t>();
  stat.st_rdev = fuzzed_data_provider.ConsumeIntegral<dev_t>();
  stat.st_size = fuzzed_data_provider.ConsumeIntegral<off64_t>();
  stat.st_atime = fuzzed_data_provider.ConsumeIntegral<time_t>();
  stat.st_mtime = fuzzed_data_provider.ConsumeIntegral<time_t>();
  stat.st_ctime = fuzzed_data_provider.ConsumeIntegral<time_t>();
  stat.st_blksize = fuzzed_data_provider.ConsumeIntegral<blksize_t>();
  stat.st_blocks = fuzzed_data_provider.ConsumeIntegral<blkcnt64_t>();
  return stat;
}

// Fuzzed analog of `base::FileEnumerator`. Returns virtual FS contents but,
// with some chance, skips some entries or injects arbitrary ones.
class FuzzedFileEnumerator : public FileEnumerator {
 public:
  FuzzedFileEnumerator(const base::FilePath& path,
                       bool recursive,
                       int file_type,
                       bool fill_info,
                       const FuzzedPlatform::VirtualFs& virtual_fs,
                       FuzzedDataProvider& fuzzed_data_provider)
      : path_(path),
        recursive_(recursive),
        file_type_(file_type),
        fill_info_(fill_info),
        virtual_fs_(virtual_fs),
        fuzzed_data_provider_(fuzzed_data_provider),
        virtual_fs_iter_(virtual_fs_.begin()) {}

  base::FilePath Next() override {
    do {
      NextImpl();
    } while (current_path_.empty() && virtual_fs_iter_ != virtual_fs_.end());
    return current_path_;
  }

  FileInfo GetInfo() override {
    DCHECK(fill_info_);
    return current_file_info_;
  }

 private:
  void NextImpl() {
    current_path_ = base::FilePath();
    current_file_info_ = FileInfo();
    while (virtual_fs_iter_ != virtual_fs_.end() &&
           !IsMatching(virtual_fs_iter_->first, virtual_fs_iter_->second)) {
      ++virtual_fs_iter_;
    }
    switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
      case FuzzResultStrategy::kSimulate: {
        if (virtual_fs_iter_ == virtual_fs_.end()) {
          return;
        }
        current_path_ = virtual_fs_iter_->first;
        if (fill_info_) {
          current_file_info_ =
              FileInfo(current_path_, GetStat(virtual_fs_iter_->second));
        }
        ++virtual_fs_iter_;
        return;
      }
      case FuzzResultStrategy::kPretendSuccess: {
        current_path_ = GenerateArbitraryDescendant(path_, recursive_,
                                                    fuzzed_data_provider_);
        if (fill_info_) {
          current_file_info_ = FileInfo(
              current_path_, GenerateArbitraryStat(fuzzed_data_provider_));
        }
        return;
      }
      case FuzzResultStrategy::kPretendFailure: {
        // Pretend the next file in the virtual FS disappeared.
        if (virtual_fs_iter_ != virtual_fs_.end()) {
          ++virtual_fs_iter_;
        }
        return;
      }
    }
  }

  bool IsMatching(const base::FilePath& candidate_path,
                  const FuzzedPlatform::VirtualFsEntry& candidate) const {
    if (!IsPathDescendant(candidate_path, path_, recursive_)) {
      return false;
    }
    if (candidate.is_dir && !(file_type_ & base::FileEnumerator::DIRECTORIES)) {
      return false;
    }
    if (!candidate.is_dir && !(file_type_ & base::FileEnumerator::FILES)) {
      return false;
    }
    return true;
  }

  const base::FilePath path_;
  const bool recursive_;
  const int file_type_;
  const bool fill_info_;
  const FuzzedPlatform::VirtualFs& virtual_fs_;
  FuzzedDataProvider& fuzzed_data_provider_;
  FuzzedPlatform::VirtualFs::const_iterator virtual_fs_iter_;
  base::FilePath current_path_;
  FileInfo current_file_info_;
};

Blob GenerateArbitraryFileContents(const Blob& original_contents,
                                   FuzzedDataProvider& fuzzed_data_provider) {
  enum class Strategy {
    kCreateRandom,
    kCreateRandomProto,
    kMutateOriginal,
    // Must be the last item.
    kMaxValue = kMutateOriginal
  };
  switch (fuzzed_data_provider.ConsumeEnum<Strategy>()) {
    case Strategy::kCreateRandom: {
      return BlobFromString(fuzzed_data_provider.ConsumeRandomLengthString());
    }
    case Strategy::kCreateRandomProto: {
      FuzzedProtoGenerator generator(fuzzed_data_provider);
      return generator.Generate();
    }
    case Strategy::kMutateOriginal: {
      const size_t max_length =
          std::max(original_contents.size() * kBlobMutationSizeFactor,
                   kBlobMutationDefaultMaxSize);
      return MutateBlob(original_contents, /*min_length=*/0, max_length,
                        &fuzzed_data_provider);
    }
  }
}

}  // namespace

FuzzedPlatform::FuzzedPlatform(FuzzedDataProvider& fuzzed_data_provider)
    : fuzzed_data_provider_(fuzzed_data_provider) {
  // As a baseline, the root folder is always there.
  virtual_fs_[base::FilePath("/")] = VirtualFsEntry{
      .is_dir = true,
      .permissions = kDefaultDirPermissions,
      .user_id = kDefaultUserId,
      .group_id = kDefaultGroupId,
  };
}

FuzzedPlatform::~FuzzedPlatform() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

bool FuzzedPlatform::Mount(const base::FilePath& from,
                           const base::FilePath& to,
                           const std::string& /*type*/,
                           uint32_t /*mount_flags*/,
                           const std::string& /*mount_options*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(from);
  AssertIsValidAbsolutePath(to);
  // Mounts are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::Bind(const base::FilePath& from,
                          const base::FilePath& to,
                          RemountOption /*remount*/,
                          bool /*nosymfollow*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(from);
  AssertIsValidAbsolutePath(to);
  // Mounts are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::Unmount(const base::FilePath& path,
                             bool /*lazy*/,
                             bool* was_busy) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Mounts are not simulated, hence return random result.
  if (GetArbitraryOutcome()) {
    return true;
  }
  if (was_busy) {
    *was_busy = fuzzed_data_provider_.ConsumeBool();
  }
  return false;
}

void FuzzedPlatform::LazyUnmount(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Mounts are not simulated, so nothing to do here.
}

ExpireMountResult FuzzedPlatform::ExpireMount(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Mounts are not simulated, so return random result.
  return fuzzed_data_provider_.ConsumeEnum<ExpireMountResult>();
}

bool FuzzedPlatform::GetLoopDeviceMounts(
    std::multimap<const base::FilePath, const base::FilePath>* mounts) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(mounts);
  return GetLoopDeviceMountsImpl(/*key_prefix=*/base::FilePath("/"), mounts);
}

bool FuzzedPlatform::GetMountsBySourcePrefix(
    const base::FilePath& from_prefix,
    std::multimap<const base::FilePath, const base::FilePath>* mounts) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(from_prefix);
  CHECK(mounts);
  return GetLoopDeviceMountsImpl(
      /*key_prefix=*/from_prefix.AsEndingWithSeparator(), mounts);
}

bool FuzzedPlatform::GetMountsByDevicePrefix(
    const std::string& from_prefix,
    std::multimap<const base::FilePath, const base::FilePath>* mounts) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(mounts);
  return GetLoopDeviceMountsImpl(base::FilePath(from_prefix), mounts);
}

bool FuzzedPlatform::IsDirectoryMounted(const base::FilePath& directory) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(directory);
  // Mounts are not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeBool();
}

std::optional<std::vector<bool>> FuzzedPlatform::AreDirectoriesMounted(
    const std::vector<base::FilePath>& directories) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  for (const auto& path : directories) {
    CHECK(path.IsAbsolute()) << "path=" << path;
    CHECK(!path.ReferencesParent()) << "path=" << path;
  }
  // Mounts are not simulated, hence return random result.
  if (!GetArbitraryOutcome()) {
    return std::nullopt;
  }
  std::vector<bool> result(directories.size());
  for (size_t i = 0; i < result.size(); ++i) {
    result[i] = fuzzed_data_provider_.ConsumeBool();
  }
  return result;
}

std::unique_ptr<brillo::Process> FuzzedPlatform::CreateProcessInstance() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return std::make_unique<testing::NiceMock<brillo::ProcessMock>>();
}

bool FuzzedPlatform::GetOwnership(const base::FilePath& path,
                                  uid_t* user_id,
                                  gid_t* group_id,
                                  bool /*follow_links*/) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(user_id);
  CHECK(group_id);
  return GetFileInfo(path, /*out_permissions=*/nullptr, user_id, group_id);
}

bool FuzzedPlatform::SetOwnership(const base::FilePath& path,
                                  uid_t user_id,
                                  gid_t group_id,
                                  bool /*follow_links*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return SetFileInfo(path,
                     /*expect_is_dir=*/false, /*new_mode=*/std::nullopt,
                     user_id, group_id);
}

bool FuzzedPlatform::GetPermissions(const base::FilePath& path,
                                    mode_t* mode) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(mode);
  return GetFileInfo(path, mode, /*user_id=*/nullptr,
                     /*group_id=*/nullptr);
}

bool FuzzedPlatform::SetPermissions(const base::FilePath& path, mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return SetFileInfo(path,
                     /*expect_is_dir=*/false, mode,
                     /*new_user_id=*/std::nullopt,
                     /*new_group_id=*/std::nullopt);
}

int64_t FuzzedPlatform::AmountOfFreeDiskSpace(
    const base::FilePath& path) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Disk space is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
}

int64_t FuzzedPlatform::GetQuotaCurrentSpaceForUid(const base::FilePath& device,
                                                   uid_t /*user_id*/) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device);
  // Quota is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
}

int64_t FuzzedPlatform::GetQuotaCurrentSpaceForGid(const base::FilePath& device,
                                                   gid_t /*group_id*/) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device);
  // Quota is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
}

int64_t FuzzedPlatform::GetQuotaCurrentSpaceForProjectId(
    const base::FilePath& device, int /*project_id*/) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device);
  // Quota is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
}

bool FuzzedPlatform::GetQuotaProjectId(const base::FilePath& path,
                                       int* project_id) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(project_id);
  // Quota is not simulated, hence return random result.
  if (!GetArbitraryOutcome()) {
    return false;
  }
  *project_id = fuzzed_data_provider_.ConsumeIntegralInRange<int>(
      0, std::numeric_limits<int32_t>::max());
  return true;
}

bool FuzzedPlatform::SetQuotaProjectId(const base::FilePath& path,
                                       int /*project_id*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Quota is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::SetQuotaProjectIdWithFd(int /*project_id*/,
                                             int /*fd*/,
                                             int* out_error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(out_error);
  // Quota is not simulated, hence return random result.
  int code = fuzzed_data_provider_.ConsumeIntegralInRange<int>(
      0, std::numeric_limits<int>::max());
  if (code != 0) {
    *out_error = code;
    return false;
  }
  return true;
}

bool FuzzedPlatform::SetQuotaProjectInheritanceFlagWithFd(bool /*enable*/,
                                                          int /*fd*/,
                                                          int* out_error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(out_error);
  // Quota is not simulated, hence return random result.
  int code = fuzzed_data_provider_.ConsumeIntegralInRange<int>(
      0, std::numeric_limits<int>::max());
  if (code != 0) {
    *out_error = code;
    return false;
  }
  return true;
}

bool FuzzedPlatform::FileExists(const base::FilePath& path) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate:
      return virtual_fs_.count(CanonicalizePath(path)) > 0;
    case FuzzResultStrategy::kPretendSuccess:
      return true;
    case FuzzResultStrategy::kPretendFailure:
      return false;
  }
}

int FuzzedPlatform::Access(const base::FilePath& path, uint32_t flag) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return -1;
      }
      mode_t permissions = iter->second.permissions;
      bool failed_read = (flag & R_OK) && !(permissions & S_IRUSR);
      bool failed_write = (flag & W_OK) && !(permissions & S_IWUSR);
      bool failed_exec = (flag & X_OK) && !(permissions & S_IXUSR);
      if (failed_read || failed_write || failed_exec) {
        return -1;
      }
      return 0;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return 0;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return -1;
    }
  }
}

bool FuzzedPlatform::DirectoryExists(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      return iter != virtual_fs_.end() && iter->second.is_dir;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetFileSize(const base::FilePath& path, int64_t* size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(size);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      *size = iter->second.file_contents.size();
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      *size = fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
          0, std::numeric_limits<int64_t>::max());
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

int64_t FuzzedPlatform::ComputeDirectoryDiskUsage(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Disk space is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
}

FILE* FuzzedPlatform::OpenFile(const base::FilePath& path, const char* mode) {
  // We don't simulate reading/writing of data; currently, all callsites of
  // `OpenFile()` use it only for creating empty files. Zero couldn't be chosen
  // as `fmemopen()` rejects it.
  constexpr int kMemopenSize = 1;

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(mode);
  if (std::string(mode) != "wx") {
    // We don't simulate all possible modes since it's a lot of work with little
    // benefit until we have callsites that use other modes.
    LOG(FATAL) << "Fuzzed OpenFile is not simulated for mode=" << mode;
  }
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_path = CanonicalizePath(path);
      const auto dir_iter = virtual_fs_.find(canonical_path.DirName());
      if (dir_iter == virtual_fs_.end() || !dir_iter->second.is_dir) {
        return nullptr;
      }
      if (virtual_fs_.count(canonical_path)) {
        return nullptr;
      }
      virtual_fs_[canonical_path] = VirtualFsEntry{
          .is_dir = false,
          .permissions = kDefaultFilePermissions,
          .user_id = kDefaultUserId,
          .group_id = kDefaultGroupId,
      };
      return fmemopen(/*buf=*/nullptr, kMemopenSize, mode);
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return fmemopen(/*buf=*/nullptr, kMemopenSize, mode);
    }
    case FuzzResultStrategy::kPretendFailure: {
      return nullptr;
    }
  }
}

bool FuzzedPlatform::CloseFile(FILE* file) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(file);
  // Close the file regardless of the strategy chosen below, to avoid leaks.
  const bool real_result = base::CloseFile(file);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate:
      return real_result;
    case FuzzResultStrategy::kPretendSuccess:
      return true;
    case FuzzResultStrategy::kPretendFailure:
      return false;
  }
}

void FuzzedPlatform::InitializeFile(base::File* file,
                                    const base::FilePath& path,
                                    uint32_t flags) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(FATAL) << "Not simulated yet";
}

bool FuzzedPlatform::LockFile(int /*fd*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // File locking is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::ReadFile(const base::FilePath& path, Blob* blob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(blob);
  return ReadFileImpl(path, blob);
}

bool FuzzedPlatform::ReadFileToString(const base::FilePath& path,
                                      std::string* str) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(str);
  Blob blob;
  if (!ReadFileImpl(path, &blob)) {
    return false;
  }
  *str = BlobToString(blob);
  return true;
}

bool FuzzedPlatform::ReadFileToSecureBlob(const base::FilePath& path,
                                          SecureBlob* sblob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(sblob);
  Blob blob;
  if (!ReadFileImpl(path, &blob)) {
    return false;
  }
  sblob->assign(blob.begin(), blob.end());
  return true;
}

bool FuzzedPlatform::WriteFile(const base::FilePath& path, const Blob& blob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, blob, kDefaultFilePermissions);
}

bool FuzzedPlatform::WriteSecureBlobToFile(const base::FilePath& path,
                                           const SecureBlob& sblob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, Blob(sblob.begin(), sblob.end()),
                       kDefaultFilePermissions);
}

bool FuzzedPlatform::WriteStringToFile(const base::FilePath& path,
                                       const std::string& str) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, BlobFromString(str), kDefaultFilePermissions);
}

bool FuzzedPlatform::WriteArrayToFile(const base::FilePath& path,
                                      const char* data,
                                      size_t size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(data || !size);
  return WriteFileImpl(path, size ? Blob(data, data + size) : Blob(),
                       kDefaultFilePermissions);
}

bool FuzzedPlatform::WriteFileAtomic(const base::FilePath& path,
                                     const Blob& blob,
                                     mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, blob, mode);
}

bool FuzzedPlatform::WriteSecureBlobToFileAtomic(const base::FilePath& path,
                                                 const SecureBlob& sblob,
                                                 mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, Blob(sblob.begin(), sblob.end()), mode);
}

bool FuzzedPlatform::WriteStringToFileAtomic(const base::FilePath& path,
                                             const std::string& data,
                                             mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, BlobFromString(data), mode);
}

bool FuzzedPlatform::WriteFileAtomicDurable(const base::FilePath& path,
                                            const Blob& blob,
                                            mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, blob, mode);
}

bool FuzzedPlatform::WriteSecureBlobToFileAtomicDurable(
    const base::FilePath& path, const SecureBlob& sblob, mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, Blob(sblob.begin(), sblob.end()), mode);
}

bool FuzzedPlatform::WriteStringToFileAtomicDurable(const base::FilePath& path,
                                                    const std::string& str,
                                                    mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return WriteFileImpl(path, BlobFromString(str), mode);
}

bool FuzzedPlatform::TouchFileDurable(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      return iter != virtual_fs_.end() && !iter->second.is_dir;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::DeleteFile(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return DeleteImpl(path, /*recursive=*/false);
}

bool FuzzedPlatform::DeletePathRecursively(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return DeleteImpl(path, /*recursive=*/true);
}

bool FuzzedPlatform::DeleteFileDurable(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return DeleteImpl(path, /*recursive=*/false);
}

bool FuzzedPlatform::CreateDirectory(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return CreateDirectoryImpl(path, kDefaultDirPermissions, kDefaultUserId,
                             kDefaultGroupId);
}

bool FuzzedPlatform::EnumerateDirectoryEntries(
    const base::FilePath& path,
    bool recursive,
    std::vector<base::FilePath>* ent_list) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(ent_list);
  FuzzedFileEnumerator en(
      path, recursive,
      base::FileEnumerator::FILES | base::FileEnumerator::DIRECTORIES,
      /*fill_info=*/false, virtual_fs_, fuzzed_data_provider_);
  for (base::FilePath path = en.Next(); !path.empty(); path = en.Next()) {
    ent_list->push_back(path);
  }
  // The real implementation always returns `true`, so do we.
  return true;
}

bool FuzzedPlatform::IsDirectoryEmpty(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_path = CanonicalizePath(path);
      for (const auto& [item_path, item] : virtual_fs_) {
        if (canonical_path.IsParent(item_path)) {
          return false;
        }
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

FileEnumerator* FuzzedPlatform::GetFileEnumerator(const base::FilePath& path,
                                                  bool recursive,
                                                  int file_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  return new FuzzedFileEnumerator(CanonicalizePath(path), recursive, file_type,
                                  /*fill_info=*/true, virtual_fs_,
                                  fuzzed_data_provider_);
}

bool FuzzedPlatform::Stat(const base::FilePath& path,
                          base::stat_wrapper_t* buf) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(buf);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      *buf = GetStat(iter->second);
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      *buf = GenerateArbitraryStat(fuzzed_data_provider_);
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::HasExtendedFileAttribute(const base::FilePath& path,
                                              const std::string& name) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      return iter->second.extended_attrs.count(name) > 0;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::ListExtendedFileAttributes(
    const base::FilePath& path, std::vector<std::string>* attr_list) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(attr_list);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      for (const auto& [name, value] : iter->second.extended_attrs) {
        attr_list->push_back(name);
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      for (;;) {
        std::string attr = fuzzed_data_provider_.ConsumeRandomLengthString();
        if (attr.empty()) {
          break;
        }
        attr_list->push_back(attr);
      }
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetExtendedFileAttributeAsString(
    const base::FilePath& path, const std::string& name, std::string* value) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(value);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      const auto& attrs = iter->second.extended_attrs;
      const auto attr_iter = attrs.find(name);
      if (attr_iter == attrs.end()) {
        return false;
      }
      *value = attr_iter->second;
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      *value = fuzzed_data_provider_.ConsumeRandomLengthString();
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetExtendedFileAttribute(const base::FilePath& path,
                                              const std::string& name,
                                              char* value,
                                              ssize_t size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(value);
  std::string string_value;
  if (!GetExtendedFileAttributeAsString(path, name, &string_value)) {
    return false;
  }
  if (string_value.size() != size) {
    return false;
  }
  memcpy(value, string_value.c_str(), string_value.size());
  return true;
}

bool FuzzedPlatform::SetExtendedFileAttribute(const base::FilePath& path,
                                              const std::string& name,
                                              const char* value,
                                              size_t size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(value || !size);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      iter->second.extended_attrs[name] =
          size ? std::string(value, value + size) : std::string();
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::RemoveExtendedFileAttribute(const base::FilePath& path,
                                                 const std::string& name) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      auto& attrs = iter->second.extended_attrs;
      const auto attr_iter = attrs.find(name);
      if (attr_iter == attrs.end()) {
        return false;
      }
      attrs.erase(attr_iter);
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetExtFileAttributes(const base::FilePath& path,
                                          int* flags) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(flags);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      *flags = iter->second.ext_flags;
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      *flags = fuzzed_data_provider_.ConsumeIntegralInRange<int>(
          0, std::numeric_limits<int>::max());
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::SetExtFileAttributes(const base::FilePath& path,
                                          int flags) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      iter->second.ext_flags = flags;
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::HasNoDumpFileAttribute(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      return (iter->second.ext_flags & FS_NODUMP_FL) != 0;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::Rename(const base::FilePath& from,
                            const base::FilePath& to) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(from);
  AssertIsValidAbsolutePath(to);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_from = CanonicalizePath(from);
      if (!virtual_fs_.count(canonical_from)) {
        return false;
      }
      std::vector<std::pair<base::FilePath, VirtualFsEntry>> new_entries;
      for (auto iter = virtual_fs_.begin(); iter != virtual_fs_.end();) {
        const base::FilePath& item_path = iter->first;
        if (item_path == canonical_from || canonical_from.IsParent(item_path)) {
          base::FilePath new_path = CanonicalizePath(to);
          canonical_from.AppendRelativePath(item_path, &new_path);
          new_entries.emplace_back(std::move(new_path),
                                   std::move(iter->second));
          iter = virtual_fs_.erase(iter);
        } else {
          ++iter;
        }
      }
      virtual_fs_.insert(new_entries.begin(), new_entries.end());
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

base::Time FuzzedPlatform::GetCurrentTime() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // The clocks should be mutated by the fuzzer using libchrome's mock time:
  // that way global singletons and threading primitives will know about it too.
  return base::Time::Now();
}

bool FuzzedPlatform::Copy(const base::FilePath& from,
                          const base::FilePath& to) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(from);
  AssertIsValidAbsolutePath(to);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_from = CanonicalizePath(from);
      const auto iter_from = virtual_fs_.find(canonical_from);
      if (iter_from == virtual_fs_.end() || !iter_from->second.is_dir) {
        return false;
      }
      std::vector<std::pair<base::FilePath, VirtualFsEntry>> new_entries;
      for (const auto& [entry_path, entry] : virtual_fs_) {
        if (entry_path != canonical_from &&
            !canonical_from.IsParent(entry_path)) {
          continue;
        }
        base::FilePath new_path = CanonicalizePath(to);
        canonical_from.AppendRelativePath(entry_path, &new_path);
        VirtualFsEntry new_entry = entry;
        new_entry.user_id = kDefaultUserId;
        new_entry.group_id = kDefaultGroupId;
        new_entry.permissions =
            new_entry.is_dir ? kDefaultDirPermissions : kDefaultFilePermissions;
        new_entries.emplace_back(std::move(new_path), std::move(new_entry));
      }
      virtual_fs_.insert(new_entries.begin(), new_entries.end());
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::StatVFS(const base::FilePath& path, struct statvfs* vfs) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(vfs);
  // FS stats are not simulated, hence return random result.
  if (!GetArbitraryOutcome()) {
    return false;
  }
  memset(vfs, 0, sizeof(struct statvfs));
  vfs->f_bsize = fuzzed_data_provider_.ConsumeIntegralInRange<
      unsigned long>(                                 // NOLINT(runtime/int)
      1, std::numeric_limits<unsigned long>::max());  // NOLINT(runtime/int)
  vfs->f_frsize = fuzzed_data_provider_.ConsumeIntegralInRange<
      unsigned long>(                                 // NOLINT(runtime/int)
      1, std::numeric_limits<unsigned long>::max());  // NOLINT(runtime/int)
  vfs->f_blocks = fuzzed_data_provider_.ConsumeIntegralInRange<fsblkcnt_t>(
      1, std::numeric_limits<fsblkcnt_t>::max());
  vfs->f_bfree = fuzzed_data_provider_.ConsumeIntegralInRange<fsblkcnt_t>(
      0, std::numeric_limits<fsblkcnt_t>::max());
  vfs->f_bavail = fuzzed_data_provider_.ConsumeIntegralInRange<fsblkcnt_t>(
      0, std::numeric_limits<fsblkcnt_t>::max());
  vfs->f_files = fuzzed_data_provider_.ConsumeIntegralInRange<fsfilcnt_t>(
      1, std::numeric_limits<fsfilcnt_t>::max());
  vfs->f_ffree = fuzzed_data_provider_.ConsumeIntegralInRange<fsfilcnt_t>(
      0, std::numeric_limits<fsfilcnt_t>::max());
  vfs->f_favail = fuzzed_data_provider_.ConsumeIntegralInRange<fsfilcnt_t>(
      0, std::numeric_limits<fsfilcnt_t>::max());
  vfs->f_fsid = fuzzed_data_provider_
                    .ConsumeIntegral<unsigned long>();  // NOLINT(runtime/int)
  vfs->f_flag = fuzzed_data_provider_
                    .ConsumeIntegral<unsigned long>();  // NOLINT(runtime/int)
  // Don't put extremely small or big values into `f_namemax`, in case some code
  // allocates buffers of this size.
  vfs->f_namemax =
      fuzzed_data_provider_
          .ConsumeIntegralInRange<unsigned long>(  // NOLINT(runtime/int)
              10, 10000);
  return true;
}

bool FuzzedPlatform::SameVFS(const base::FilePath& mnt_a,
                             const base::FilePath& mnt_b) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(mnt_a);
  AssertIsValidAbsolutePath(mnt_b);
  // VFS is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeBool();
}

bool FuzzedPlatform::FindFilesystemDevice(const base::FilePath& filesystem,
                                          std::string* device) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(filesystem);
  CHECK(device);
  // FS devices are not simulated, hence return random result.
  base::FilePath path(fuzzed_data_provider_.ConsumeRandomLengthString());
  if (!path.IsAbsolute() || path.ReferencesParent() ||
      path != CanonicalizePath(path)) {
    // If the generation gave invalid value, don't return it.
    return false;
  }
  *device = path.value();
  return true;
}

bool FuzzedPlatform::ReportFilesystemDetails(const base::FilePath& filesystem,
                                             const base::FilePath& logfile) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(filesystem);
  AssertIsValidAbsolutePath(logfile);
  // FS reporting is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::SetupProcessKeyring() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Keyrings are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

int FuzzedPlatform::GetDirectoryPolicyVersion(const base::FilePath& dir) const {
  // This is an arbitrarily chosen boundary for the fuzzer.
  constexpr int kMaxValue = 1000;
  // This is the minimum value that also denotes an error.
  constexpr int kMinValue = -1;

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(dir);
  // Keyrings are not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeIntegralInRange<int>(kMinValue,
                                                           kMaxValue);
}

bool FuzzedPlatform::CheckFscryptKeyIoctlSupport() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Fscrypt is not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeBool();
}

dircrypto::KeyState FuzzedPlatform::GetDirCryptoKeyState(
    const base::FilePath& dir) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(dir);
  // Keyrings are not simulated, hence return random result.
  return fuzzed_data_provider_.ConsumeEnum<dircrypto::KeyState>();
}

bool FuzzedPlatform::SetDirCryptoKey(
    const base::FilePath& dir,
    const dircrypto::KeyReference& /*key_reference*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(dir);
  // Keyrings are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::InvalidateDirCryptoKey(
    const dircrypto::KeyReference& /*key_reference*/,
    const base::FilePath& shadow_root) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(shadow_root);
  // Keyrings are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::ClearUserKeyring() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Keyrings are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::FirmwareWriteProtected() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Firmware is not simulated, hence return random result.
  return !fuzzed_data_provider_.ConsumeBool();
}

bool FuzzedPlatform::SyncFile(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      // Sync isn't simulated, but we should do sanity checks.
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      return iter != virtual_fs_.end() && !iter->second.is_dir;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::SyncDirectory(const base::FilePath& path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      // Sync isn't simulated, but we should do sanity checks.
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      return iter != virtual_fs_.end() && iter->second.is_dir;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

void FuzzedPlatform::Sync() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Nothing to simulate here.
}

bool FuzzedPlatform::CreateSymbolicLink(const base::FilePath& path,
                                        const base::FilePath& target) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(!target.empty());
  CHECK(!target.ReferencesParent());
  // Symlinks are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::ReadLink(const base::FilePath& path,
                              base::FilePath* target) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK(target);
  // Symlinks are not simulated, hence return random result.
  if (!GetArbitraryOutcome()) {
    return false;
  }
  *target =
      GenerateArbitraryDescendant(/*ancestor=*/base::FilePath("/"),
                                  /*recursive=*/true, fuzzed_data_provider_);
  return true;
}

bool FuzzedPlatform::SetFileTimes(const base::FilePath& path,
                                  const struct timespec& atime,
                                  const struct timespec& mtime,
                                  bool follow_links) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // File times are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::SendFile(int fd_to,
                              int fd_from,
                              off_t /*offset*/,
                              size_t /*count*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK_GE(fd_to, 0);
  CHECK_GE(fd_from, 0);
  // File descriptors are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::CreateSparseFile(const base::FilePath& path,
                                      int64_t /*size*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Don't allocate `size` bytes here, since the number can be big and as full
  // simulation of sparse files is not crucial for the fuzzer.
  return WriteFileImpl(path, Blob(), kDefaultFilePermissions);
}

bool FuzzedPlatform::GetBlkSize(const base::FilePath& device, uint64_t* size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device);
  CHECK(size);
  // FS blocks are not simulated, hence return random result.
  *size = fuzzed_data_provider_.ConsumeIntegralInRange<uint64_t>(
      0, std::numeric_limits<uint64_t>::max());
  return *size > 0;
}

bool FuzzedPlatform::DetachLoop(const base::FilePath& device_path) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device_path);
  // Loop devices are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::DiscardDevice(const base::FilePath& device) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device);
  // Loop devices are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

std::vector<Platform::LoopDevice> FuzzedPlatform::GetAttachedLoopDevices() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // Loop devices are not simulated, hence return random result.
  std::vector<LoopDevice> loop_devices;
  for (;;) {
    const base::FilePath backing_file(
        fuzzed_data_provider_.ConsumeRandomLengthString());
    const base::FilePath device(
        fuzzed_data_provider_.ConsumeRandomLengthString());
    if (!backing_file.IsAbsolute() || backing_file.ReferencesParent() ||
        backing_file != CanonicalizePath(backing_file) ||
        !device.IsAbsolute() || device.ReferencesParent() ||
        device != CanonicalizePath(device)) {
      // Treat an invalidly generated pair as a signal to finish generation.
      break;
    }
    loop_devices.push_back(LoopDevice{
        .backing_file = backing_file,
        .device = device,
    });
  }
  return loop_devices;
}

bool FuzzedPlatform::FormatExt4(const base::FilePath& file,
                                const std::vector<std::string>& /*opts*/,
                                uint64_t /*blocks*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(file);
  // FS properties are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::Tune2Fs(const base::FilePath& file,
                             const std::vector<std::string>& /*opts*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(file);
  // FS properties are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::ResizeFilesystem(const base::FilePath& file,
                                      uint64_t /*blocks*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(file);
  // FS properties are not simulated, hence return random result.
  return GetArbitraryOutcome();
}

std::optional<std::string> FuzzedPlatform::GetSELinuxContextOfFD(int /*fd*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // SELinux is not simulated, hence return random result.
  std::string context = fuzzed_data_provider_.ConsumeRandomLengthString();
  if (context.empty()) {
    return std::nullopt;
  }
  return context;
}

bool FuzzedPlatform::SetSELinuxContext(const base::FilePath& path,
                                       const std::string& /*context*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // SELinux is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::RestoreSELinuxContexts(const base::FilePath& path,
                                            bool /*recursive*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // SELinux is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::SafeDirChmod(const base::FilePath& path, mode_t mode) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return SetFileInfo(path,
                     /*expect_is_dir=*/true, mode, /*new_user_id=*/std::nullopt,
                     /*new_group_id=*/std::nullopt);
}

bool FuzzedPlatform::SafeDirChown(const base::FilePath& path,
                                  uid_t user_id,
                                  gid_t group_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return SetFileInfo(path, /*expect_is_dir=*/true, /*new_mode=*/std::nullopt,
                     user_id, group_id);
}

bool FuzzedPlatform::SafeCreateDirAndSetOwnershipAndPermissions(
    const base::FilePath& path, mode_t mode, uid_t user_id, gid_t gid) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return CreateDirectoryImpl(path, mode, user_id, gid);
}

bool FuzzedPlatform::UdevAdmSettle(const base::FilePath& device_path,
                                   bool /*wait_for_device*/) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(device_path);
  // Adm is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

bool FuzzedPlatform::IsStatefulLogicalVolumeSupported() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // LVM is not simulated, hence return random result.
  return GetArbitraryOutcome();
}

base::FilePath FuzzedPlatform::GetStatefulDevice() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // The devices are not simulated, hence return random result.
  base::FilePath path(fuzzed_data_provider_.ConsumeRandomLengthString());
  if (!path.IsAbsolute() || path.ReferencesParent() ||
      path != CanonicalizePath(path)) {
    // If the generation gave invalid value, return an empty value instead.
    return base::FilePath();
  }
  return path;
}

brillo::LoopDeviceManager* FuzzedPlatform::GetLoopDeviceManager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return &loop_device_manager_;
}

brillo::LogicalVolumeManager* FuzzedPlatform::GetLogicalVolumeManager() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // TODO(b/254864841): Fuzz mock methods.
  return &logical_volume_manager_;
}

bool FuzzedPlatform::GetArbitraryOutcome() const {
  // Negation is used in order to let fuzzer discover the "successful" scenario
  // of code-under-test more easily (when the input blob contains lots of zeroes
  // or is simply too short).
  return !fuzzed_data_provider_.ConsumeBool();
}

bool FuzzedPlatform::WriteFileImpl(const base::FilePath& path,
                                   Blob blob,
                                   mode_t permissions) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK_NE(path.StripTrailingSeparators(), path.DirName()) << "path=" << path;
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_path = CanonicalizePath(path);
      const auto dir_iter = virtual_fs_.find(canonical_path.DirName());
      if (dir_iter == virtual_fs_.end()) {
        // Parent directory doesn't exist.
        return false;
      }
      const auto iter = virtual_fs_.find(canonical_path);
      if (iter != virtual_fs_.end() && iter->second.is_dir) {
        // A directory with the given path exists.
        return false;
      }
      virtual_fs_[canonical_path] = VirtualFsEntry{
          .is_dir = false,
          .file_contents = std::move(blob),
          .permissions = permissions,
          .user_id = kDefaultUserId,
          .group_id = kDefaultGroupId,
      };
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

base::UnguessableToken FuzzedPlatform::CreateUnguessableToken() {
  uint64_t high, low;
  // Loop until we get suitable values (`UnguessableToken` forbids all-zeroes).
  do {
    high = random_engine_64_();
    low = random_engine_64_();
  } while (high == 0 && low == 0);
  std::optional<base::UnguessableToken> token =
      base::UnguessableToken::Deserialize(high, low);
  CHECK(token.has_value());
  return *token;
}

bool FuzzedPlatform::ReadFileImpl(const base::FilePath& path, Blob* blob) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  CHECK_NE(path.StripTrailingSeparators(), path.DirName()) << "path=" << path;
  const auto iter = virtual_fs_.find(CanonicalizePath(path));
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      if (iter == virtual_fs_.end() || iter->second.is_dir) {
        return false;
      }
      *blob = iter->second.file_contents;
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      *blob = GenerateArbitraryFileContents(
          iter != virtual_fs_.end() ? iter->second.file_contents : Blob(),
          fuzzed_data_provider_);
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::CreateDirectoryImpl(const base::FilePath& path,
                                         mode_t permissions,
                                         uid_t user_id,
                                         gid_t group_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Choose among a few ways to generate the result.
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_path = CanonicalizePath(path);
      // Check none of ancestors is a regular file.
      for (base::FilePath current = canonical_path;
           current != base::FilePath("/"); current = current.DirName()) {
        const auto iter = virtual_fs_.find(current);
        if (iter != virtual_fs_.end() && !iter->second.is_dir) {
          return false;
        }
      }
      // Create each ancestor until reaching an existing one.
      for (base::FilePath current = canonical_path;
           current != base::FilePath("/"); current = current.DirName()) {
        if (virtual_fs_.find(current) != virtual_fs_.end()) {
          break;
        }
        virtual_fs_[current] = VirtualFsEntry{
            .is_dir = true,
            .permissions = permissions,
            .user_id = user_id,
            .group_id = group_id,
        };
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::DeleteImpl(const base::FilePath& path, bool recursive) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  // Choose among a few ways to generate the result.
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const base::FilePath canonical_path = CanonicalizePath(path);
      if (!recursive) {
        // Check there's no subdirectory in the virtual FS.
        for (const auto& [entry_path, entry] : virtual_fs_) {
          if (entry_path.DirName() == canonical_path && entry.is_dir) {
            return false;
          }
        }
      }
      for (auto iter = virtual_fs_.begin(); iter != virtual_fs_.end();) {
        const auto& [entry_path, entry] = *iter;
        if (entry_path == canonical_path ||
            IsPathDescendant(entry_path, canonical_path, recursive)) {
          iter = virtual_fs_.erase(iter);
        } else {
          ++iter;
        }
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::SetFileInfo(const base::FilePath& path,
                                 bool expect_is_dir,
                                 std::optional<mode_t> new_permissions,
                                 std::optional<uid_t> new_user_id,
                                 std::optional<gid_t> new_group_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      // Use virtual FS.
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      VirtualFsEntry& entry = iter->second;
      if (expect_is_dir && !entry.is_dir) {
        return false;
      }
      if (new_permissions.has_value()) {
        entry.permissions = new_permissions.value();
      }
      if (new_user_id.has_value()) {
        entry.user_id = new_user_id.value();
      }
      if (new_group_id.has_value()) {
        entry.group_id = new_group_id.value();
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetFileInfo(const base::FilePath& path,
                                 mode_t* out_permissions,
                                 uid_t* out_user_id,
                                 gid_t* out_group_id) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AssertIsValidAbsolutePath(path);
  switch (fuzzed_data_provider_.ConsumeEnum<FuzzResultStrategy>()) {
    case FuzzResultStrategy::kSimulate: {
      const auto iter = virtual_fs_.find(CanonicalizePath(path));
      if (iter == virtual_fs_.end()) {
        return false;
      }
      const VirtualFsEntry& entry = iter->second;
      if (out_permissions) {
        *out_permissions = entry.permissions;
      }
      if (out_user_id) {
        *out_user_id = entry.user_id;
      }
      if (out_group_id) {
        *out_group_id = entry.group_id;
      }
      return true;
    }
    case FuzzResultStrategy::kPretendSuccess: {
      if (out_permissions) {
        *out_permissions =
            fuzzed_data_provider_.ConsumeIntegralInRange<mode_t>(0, 0777);
      }
      if (out_user_id) {
        *out_user_id = fuzzed_data_provider_.ConsumeIntegral<uid_t>();
      }
      if (out_group_id) {
        *out_group_id = fuzzed_data_provider_.ConsumeIntegral<gid_t>();
      }
      return true;
    }
    case FuzzResultStrategy::kPretendFailure: {
      return false;
    }
  }
}

bool FuzzedPlatform::GetLoopDeviceMountsImpl(
    const base::FilePath& key_prefix,
    std::multimap<const base::FilePath, const base::FilePath>* mounts) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(mounts);
  // Mounting is not simulated, hence return random result.
  if (!GetArbitraryOutcome()) {
    return false;
  }
  for (;;) {
    const base::FilePath key(key_prefix.value() +
                             fuzzed_data_provider_.ConsumeRandomLengthString());
    const base::FilePath value(
        fuzzed_data_provider_.ConsumeRandomLengthString());
    if (!key.IsAbsolute() || key.ReferencesParent() ||
        key != CanonicalizePath(key) || !value.IsAbsolute() ||
        value.ReferencesParent() || value != CanonicalizePath(value)) {
      // Treat an invalidly generated pair as a signal to finish generation.
      break;
    }
    mounts->emplace(key, value);
  }
  return !mounts->empty();
}

}  // namespace cryptohome
