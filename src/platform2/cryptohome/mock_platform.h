// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_PLATFORM_H_
#define CRYPTOHOME_MOCK_PLATFORM_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/time/time.h>
#include <base/unguessable_token.h>
#include <brillo/process/process_mock.h>
#include <gmock/gmock.h>

#include "cryptohome/fake_platform.h"
#include "cryptohome/platform.h"

namespace cryptohome {

class MockFileEnumerator : public FileEnumerator {
 public:
  MockFileEnumerator() {
    ON_CALL(*this, Next())
        .WillByDefault(::testing::Invoke(this, &MockFileEnumerator::MockNext));
    ON_CALL(*this, GetInfo())
        .WillByDefault(
            ::testing::Invoke(this, &MockFileEnumerator::MockGetInfo));
  }
  virtual ~MockFileEnumerator() {}

  void AddFileEntry(base::FilePath path) {
    // Add a placeholder struct stat.
    base::stat_wrapper_t s;
    entries_.emplace_back(FileInfo(path, s));
  }

  MOCK_METHOD(base::FilePath, Next, (), (override));
  MOCK_METHOD(FileInfo, GetInfo, (), (override));

  std::vector<FileInfo> entries_;

 protected:
  virtual base::FilePath MockNext() {
    if (entries_.empty())
      return base::FilePath();
    current_ = entries_.at(0);
    entries_.erase(entries_.begin(), entries_.begin() + 1);
    return current_.GetName();
  }
  virtual const FileInfo& MockGetInfo() { return current_; }
  FileInfo current_;
};

ACTION(CallComputeDirectoryDiskUsage) {
  return Platform().ComputeDirectoryDiskUsage(arg0);
}
ACTION(CallReportFilesystemDetails) {
  return Platform().ReportFilesystemDetails(arg0, arg1);
}
ACTION(CallFindFilesystemDevice) {
  return Platform().FindFilesystemDevice(arg0, arg1);
}

class MockPlatform : public Platform {
 public:
  MockPlatform();
  virtual ~MockPlatform();

  MOCK_METHOD(FileEnumerator*,
              GetFileEnumerator,
              (const base::FilePath&, bool, int),
              (override));
  MOCK_METHOD(bool,
              Rename,
              (const base::FilePath&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              Copy,
              (const base::FilePath&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              EnumerateDirectoryEntries,
              (const base::FilePath&, bool, std::vector<base::FilePath>*),
              (override));
  MOCK_METHOD(bool, IsDirectoryEmpty, (const base::FilePath&), (override));
  MOCK_METHOD(bool, TouchFileDurable, (const base::FilePath& path), (override));
  MOCK_METHOD(bool, DeleteFile, (const base::FilePath&), (override));
  MOCK_METHOD(bool, DeletePathRecursively, (const base::FilePath&), (override));
  MOCK_METHOD(bool, DeleteFileDurable, (const base::FilePath&), (override));
  MOCK_METHOD(bool, DeleteFileSecurely, (const base::FilePath&), (override));
  MOCK_METHOD(bool, FileExists, (const base::FilePath&), (const, override));
  MOCK_METHOD(bool, DirectoryExists, (const base::FilePath&), (override));
  MOCK_METHOD(int, Access, (const base::FilePath&, uint32_t), (override));
  MOCK_METHOD(bool,
              CreateDirectoryAndGetError,
              (const base::FilePath&, base::File::Error*),
              (override));
  MOCK_METHOD(bool, CreateDirectory, (const base::FilePath&), (override));
  MOCK_METHOD(bool,
              CreateSparseFile,
              (const base::FilePath&, int64_t),
              (override));
  MOCK_METHOD(bool, SyncFile, (const base::FilePath&), (override));
  MOCK_METHOD(bool, SyncDirectory, (const base::FilePath&), (override));
  MOCK_METHOD(void, Sync, (), (override));
  MOCK_METHOD(bool,
              CreateSymbolicLink,
              (const base::FilePath&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              ReadLink,
              (const base::FilePath&, base::FilePath*),
              (override));
  MOCK_METHOD(bool,
              SetFileTimes,
              (const base::FilePath&,
               const struct timespec&,
               const struct timespec&,
               bool),
              (override));
  MOCK_METHOD(bool, SendFile, (int, int, off_t, size_t), (override));
  MOCK_METHOD(void,
              InitializeFile,
              (base::File*, const base::FilePath&, uint32_t),
              (override));
  MOCK_METHOD(bool, LockFile, (int), (override));
  MOCK_METHOD(bool,
              ReadFile,
              (const base::FilePath&, brillo::Blob*),
              (override));
  MOCK_METHOD(bool,
              ReadFileToString,
              (const base::FilePath&, std::string*),
              (override));
  MOCK_METHOD(bool,
              ReadFileToSecureBlob,
              (const base::FilePath&, brillo::SecureBlob*),
              (override));
  MOCK_METHOD(bool,
              WriteFile,
              (const base::FilePath&, const brillo::Blob&),
              (override));
  MOCK_METHOD(bool,
              WriteSecureBlobToFile,
              (const base::FilePath&, const brillo::SecureBlob&),
              (override));
  MOCK_METHOD(bool,
              WriteFileAtomic,
              (const base::FilePath&, const brillo::Blob&, mode_t mode),
              (override));
  MOCK_METHOD(bool,
              WriteSecureBlobToFileAtomic,
              (const base::FilePath&, const brillo::SecureBlob&, mode_t mode),
              (override));
  MOCK_METHOD(bool,
              WriteFileAtomicDurable,
              (const base::FilePath&, const brillo::Blob&, mode_t mode),
              (override));
  MOCK_METHOD(bool,
              WriteSecureBlobToFileAtomicDurable,
              (const base::FilePath&, const brillo::SecureBlob&, mode_t mode),
              (override));
  MOCK_METHOD(bool,
              WriteStringToFile,
              (const base::FilePath&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              WriteStringToFileAtomicDurable,
              (const base::FilePath&, const std::string&, mode_t mode),
              (override));
  MOCK_METHOD(bool,
              WriteArrayToFile,
              (const base::FilePath& path, const char* data, size_t size),
              (override));
  MOCK_METHOD(FILE*,
              OpenFile,
              (const base::FilePath&, const char*),
              (override));
  MOCK_METHOD(bool,
              CloseFile,
              (FILE*),
              (override));  // NOLINT(readability/function)
  MOCK_METHOD(bool, GetFileSize, (const base::FilePath&, int64_t*), (override));
  MOCK_METHOD(bool,
              Stat,
              (const base::FilePath&, base::stat_wrapper_t*),
              (override));
  MOCK_METHOD(bool,
              HasExtendedFileAttribute,
              (const base::FilePath&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              ListExtendedFileAttributes,
              (const base::FilePath&, std::vector<std::string>*),
              (override));
  MOCK_METHOD(bool,
              GetExtendedFileAttributeAsString,
              (const base::FilePath&, const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              GetExtendedFileAttribute,
              (const base::FilePath&, const std::string&, char*, ssize_t),
              (override));
  MOCK_METHOD(bool,
              SetExtendedFileAttribute,
              (const base::FilePath&, const std::string&, const char*, size_t),
              (override));
  MOCK_METHOD(bool,
              RemoveExtendedFileAttribute,
              (const base::FilePath&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              GetExtFileAttributes,
              (const base::FilePath&, int*),
              (override));
  MOCK_METHOD(bool,
              SetExtFileAttributes,
              (const base::FilePath&, int),
              (override));
  MOCK_METHOD(bool,
              HasNoDumpFileAttribute,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              GetPermissions,
              (const base::FilePath&, mode_t*),
              (const, override));
  MOCK_METHOD(bool,
              SetPermissions,
              (const base::FilePath&, mode_t),
              (override));
  MOCK_METHOD(bool, SafeDirChmod, (const base::FilePath&, mode_t), (override));
  MOCK_METHOD(bool,
              GetOwnership,
              (const base::FilePath&, uid_t*, gid_t*, bool),
              (const, override));
  MOCK_METHOD(bool,
              SetOwnership,
              (const base::FilePath&, uid_t, gid_t, bool),
              (override));
  MOCK_METHOD(bool,
              SafeDirChown,
              (const base::FilePath&, uid_t, gid_t),
              (override));
  MOCK_METHOD(bool,
              SafeCreateDirAndSetOwnershipAndPermissions,
              (const base::FilePath&, mode_t, uid_t, gid_t),
              (override));
  MOCK_METHOD(int64_t,
              AmountOfFreeDiskSpace,
              (const base::FilePath&),
              (const, override));
  MOCK_METHOD(bool,
              Mount,
              (const base::FilePath&,
               const base::FilePath&,
               const std::string&,
               uint32_t,
               const std::string&),
              (override));
  MOCK_METHOD(
      bool,
      Bind,
      (const base::FilePath&, const base::FilePath&, RemountOption, bool),
      (override));
  MOCK_METHOD(bool, Unmount, (const base::FilePath&, bool, bool*), (override));
  MOCK_METHOD(void, LazyUnmount, (const base::FilePath&), (override));
  MOCK_METHOD(bool,
              GetMountsByDevicePrefix,
              (const std::string&,
               (std::multimap<const base::FilePath, const base::FilePath>*)),
              (override));
  MOCK_METHOD(bool,
              GetLoopDeviceMounts,
              ((std::multimap<const base::FilePath, const base::FilePath>*)),
              (override));
  MOCK_METHOD(bool,
              GetMountsBySourcePrefix,
              (const base::FilePath&,
               (std::multimap<const base::FilePath, const base::FilePath>*)),
              (override));
  MOCK_METHOD(bool, IsDirectoryMounted, (const base::FilePath&), (override));
  MOCK_METHOD(std::optional<std::vector<bool>>,
              AreDirectoriesMounted,
              (const std::vector<base::FilePath>&),
              (override));

  MOCK_METHOD(brillo::LoopDeviceManager*, GetLoopDeviceManager, (), (override));
  MOCK_METHOD(brillo::LogicalVolumeManager*,
              GetLogicalVolumeManager,
              (),
              (override));

  // Calls which do not have a corresponding fake in FakePlatform.

  MOCK_METHOD(ExpireMountResult,
              ExpireMount,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(std::unique_ptr<brillo::Process>,
              CreateProcessInstance,
              (),
              (override));
  MOCK_METHOD(int64_t,
              GetQuotaCurrentSpaceForUid,
              (const base::FilePath&, uid_t),
              (const, override));
  MOCK_METHOD(int64_t,
              GetQuotaCurrentSpaceForGid,
              (const base::FilePath&, gid_t),
              (const, override));
  MOCK_METHOD(int64_t,
              GetQuotaCurrentSpaceForProjectId,
              (const base::FilePath&, int),
              (const, override));
  MOCK_METHOD(bool,
              GetQuotaProjectId,
              (const base::FilePath&, int*),
              (const, override));
  MOCK_METHOD(bool,
              SetQuotaProjectId,
              (const base::FilePath&, int),
              (override));
  MOCK_METHOD(bool, SetQuotaProjectIdWithFd, (int, int, int*), (override));
  MOCK_METHOD(bool,
              SetQuotaProjectInheritanceFlagWithFd,
              (bool, int, int*),
              (override));
  MOCK_METHOD(int64_t,
              ComputeDirectoryDiskUsage,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(base::Time, GetCurrentTime, (), (const, override));
  MOCK_METHOD(bool,
              StatVFS,
              (const base::FilePath&, struct statvfs*),
              (override));
  MOCK_METHOD(bool,
              SameVFS,
              (const base::FilePath&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              ReportFilesystemDetails,
              (const base::FilePath&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              FindFilesystemDevice,
              (const base::FilePath&, std::string*),
              (override));
  MOCK_METHOD(bool, SetupProcessKeyring, (), (override));
  MOCK_METHOD(dircrypto::KeyState,
              GetDirCryptoKeyState,
              (const base::FilePath&),
              (override));
  MOCK_METHOD(bool,
              SetDirCryptoKey,
              (const base::FilePath&, const dircrypto::KeyReference&),
              (override));
  MOCK_METHOD(int,
              GetDirectoryPolicyVersion,
              (const base::FilePath& dir),
              (const, override));
  MOCK_METHOD(bool, CheckFscryptKeyIoctlSupport, (), (const, override));
  MOCK_METHOD(bool,
              InvalidateDirCryptoKey,
              (const dircrypto::KeyReference&, const base::FilePath&),
              (override));
  MOCK_METHOD(bool, ClearUserKeyring, (), (override));
  MOCK_METHOD(bool, FirmwareWriteProtected, (), (override));
  MOCK_METHOD(bool, GetBlkSize, (const base::FilePath&, uint64_t*), (override));
  MOCK_METHOD(bool, DetachLoop, (const base::FilePath&), (override));
  MOCK_METHOD(bool, DiscardDevice, (const base::FilePath&), (override));
  MOCK_METHOD(std::vector<LoopDevice>, GetAttachedLoopDevices, (), (override));
  MOCK_METHOD(bool,
              FormatExt4,
              (const base::FilePath&,
               const std::vector<std::string>&,
               uint64_t),
              (override));
  MOCK_METHOD(bool,
              Tune2Fs,
              (const base::FilePath&, const std::vector<std::string>&),
              (override));
  MOCK_METHOD(bool,
              ResizeFilesystem,
              (const base::FilePath&, uint64_t),
              (override));
  MOCK_METHOD(bool,
              RestoreSELinuxContexts,
              (const base::FilePath&, bool),
              (override));
  MOCK_METHOD(std::optional<std::string>,
              GetSELinuxContextOfFD,
              (int fd),
              (override));
  MOCK_METHOD(bool,
              SetSELinuxContext,
              (const base::FilePath&, const std::string&),
              (override));
  MOCK_METHOD(bool, UdevAdmSettle, (const base::FilePath&, bool), (override));
  MOCK_METHOD(bool, IsStatefulLogicalVolumeSupported, (), (override));
  MOCK_METHOD(base::FilePath, GetStatefulDevice, (), (override));
  MOCK_METHOD(base::UnguessableToken, CreateUnguessableToken, (), (override));

  brillo::ProcessMock* mock_process() { return mock_process_.get(); }

  FakePlatform* GetFake() { return fake_platform_.get(); }

 private:
  std::unique_ptr<brillo::Process> MockCreateProcessInstance() {
    auto res = std::move(mock_process_);
    mock_process_ =
        std::make_unique<::testing::NiceMock<brillo::ProcessMock>>();
    return res;
  }

  std::unique_ptr<brillo::ProcessMock> mock_process_;
  std::unique_ptr<FakePlatform> fake_platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_PLATFORM_H_
