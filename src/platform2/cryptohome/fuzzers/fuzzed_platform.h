// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FUZZERS_FUZZED_PLATFORM_H_
#define CRYPTOHOME_FUZZERS_FUZZED_PLATFORM_H_

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <brillo/blkdev_utils/loop_device_fake.h>
#include <brillo/blkdev_utils/mock_lvm.h>
#include <brillo/process/process.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <gmock/gmock.h>

#include "cryptohome/dircrypto_util.h"
#include "cryptohome/platform.h"

namespace cryptohome {

// Platform implementation for use in fuzzers.
//
// It returns "random" results based on the supplied data provider.
// Additionally, to make fuzzing more effective, it performs simple simulation
// for many core operations (e.g., reading a file after having it written will,
// with some chance, return the written data). Unlike `FakePlatform`, it does
// not perform physical platform operations, for performance and isolation
// reasons.
//
// Must be used from a single sequence only (concurrent usage is forbidden).
class FuzzedPlatform : public Platform {
 public:
  struct VirtualFsEntry {
    bool is_dir = false;
    brillo::Blob file_contents;
    mode_t permissions = 0;
    uid_t user_id = 0;
    gid_t group_id = 0;
    std::map<std::string, std::string> extended_attrs;
    int ext_flags = 0;
  };
  using VirtualFs = std::map<base::FilePath, VirtualFsEntry>;

  explicit FuzzedPlatform(FuzzedDataProvider& fuzzed_data_provider);
  FuzzedPlatform(const FuzzedPlatform&) = delete;
  FuzzedPlatform& operator=(const FuzzedPlatform&) = delete;
  ~FuzzedPlatform() override;

  bool Mount(const base::FilePath& from,
             const base::FilePath& to,
             const std::string& type,
             uint32_t mount_flags,
             const std::string& mount_options) override;
  bool Bind(const base::FilePath& from,
            const base::FilePath& to,
            RemountOption remount = RemountOption::kNoRemount,
            bool nosymfollow = false) override;
  bool Unmount(const base::FilePath& path, bool lazy, bool* was_busy) override;
  void LazyUnmount(const base::FilePath& path) override;
  ExpireMountResult ExpireMount(const base::FilePath& path) override;
  bool GetLoopDeviceMounts(
      std::multimap<const base::FilePath, const base::FilePath>* mounts)
      override;
  bool GetMountsBySourcePrefix(
      const base::FilePath& from_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts)
      override;
  bool GetMountsByDevicePrefix(
      const std::string& from_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts)
      override;
  bool IsDirectoryMounted(const base::FilePath& directory) override;
  std::optional<std::vector<bool>> AreDirectoriesMounted(
      const std::vector<base::FilePath>& directories) override;
  std::unique_ptr<brillo::Process> CreateProcessInstance() override;
  bool GetOwnership(const base::FilePath& path,
                    uid_t* user_id,
                    gid_t* group_id,
                    bool follow_links) const override;
  bool SetOwnership(const base::FilePath& path,
                    uid_t user_id,
                    gid_t group_id,
                    bool follow_links) override;
  bool GetPermissions(const base::FilePath& path, mode_t* mode) const override;
  bool SetPermissions(const base::FilePath& path, mode_t mode) override;
  int64_t AmountOfFreeDiskSpace(const base::FilePath& path) const override;
  int64_t GetQuotaCurrentSpaceForUid(const base::FilePath& device,
                                     uid_t user_id) const override;
  int64_t GetQuotaCurrentSpaceForGid(const base::FilePath& device,
                                     gid_t group_id) const override;
  int64_t GetQuotaCurrentSpaceForProjectId(const base::FilePath& device,
                                           int project_id) const override;
  bool GetQuotaProjectId(const base::FilePath& path,
                         int* project_id) const override;
  bool SetQuotaProjectId(const base::FilePath& path, int project_id) override;
  bool SetQuotaProjectIdWithFd(int project_id, int fd, int* out_error) override;
  bool SetQuotaProjectInheritanceFlagWithFd(bool enable,
                                            int fd,
                                            int* out_error) override;
  bool FileExists(const base::FilePath& path) const override;
  int Access(const base::FilePath& path, uint32_t flag) override;
  bool DirectoryExists(const base::FilePath& path) override;
  bool GetFileSize(const base::FilePath& path, int64_t* size) override;
  int64_t ComputeDirectoryDiskUsage(const base::FilePath& path) override;
  FILE* OpenFile(const base::FilePath& path, const char* mode) override;
  bool CloseFile(FILE* file) override;
  void InitializeFile(base::File* file,
                      const base::FilePath& path,
                      uint32_t flags) override;
  bool LockFile(int fd) override;
  bool ReadFile(const base::FilePath& path, brillo::Blob* blob) override;
  bool ReadFileToString(const base::FilePath& path, std::string* str) override;
  bool ReadFileToSecureBlob(const base::FilePath& path,
                            brillo::SecureBlob* sblob) override;
  bool WriteFile(const base::FilePath& path, const brillo::Blob& blob) override;
  bool WriteSecureBlobToFile(const base::FilePath& path,
                             const brillo::SecureBlob& sblob) override;
  bool WriteStringToFile(const base::FilePath& path,
                         const std::string& str) override;
  bool WriteArrayToFile(const base::FilePath& path,
                        const char* data,
                        size_t size) override;
  bool WriteFileAtomic(const base::FilePath& path,
                       const brillo::Blob& blob,
                       mode_t mode) override;
  bool WriteSecureBlobToFileAtomic(const base::FilePath& path,
                                   const brillo::SecureBlob& sblob,
                                   mode_t mode) override;
  bool WriteStringToFileAtomic(const base::FilePath& path,
                               const std::string& data,
                               mode_t mode) override;
  bool WriteFileAtomicDurable(const base::FilePath& path,
                              const brillo::Blob& blob,
                              mode_t mode) override;
  bool WriteSecureBlobToFileAtomicDurable(const base::FilePath& path,
                                          const brillo::SecureBlob& sblob,
                                          mode_t mode) override;
  bool WriteStringToFileAtomicDurable(const base::FilePath& path,
                                      const std::string& str,
                                      mode_t mode) override;
  bool TouchFileDurable(const base::FilePath& path) override;
  bool DeleteFile(const base::FilePath& path) override;
  bool DeletePathRecursively(const base::FilePath& path) override;
  bool DeleteFileDurable(const base::FilePath& path) override;
  bool CreateDirectory(const base::FilePath& path) override;
  bool EnumerateDirectoryEntries(
      const base::FilePath& path,
      bool recursive,
      std::vector<base::FilePath>* ent_list) override;
  bool IsDirectoryEmpty(const base::FilePath& path) override;
  FileEnumerator* GetFileEnumerator(const base::FilePath& path,
                                    bool recursive,
                                    int file_type) override;
  bool Stat(const base::FilePath& path, base::stat_wrapper_t* buf) override;
  bool HasExtendedFileAttribute(const base::FilePath& path,
                                const std::string& name) override;
  bool ListExtendedFileAttributes(const base::FilePath& path,
                                  std::vector<std::string>* attr_list) override;
  bool GetExtendedFileAttributeAsString(const base::FilePath& path,
                                        const std::string& name,
                                        std::string* value) override;
  bool GetExtendedFileAttribute(const base::FilePath& path,
                                const std::string& name,
                                char* value,
                                ssize_t size) override;
  bool SetExtendedFileAttribute(const base::FilePath& path,
                                const std::string& name,
                                const char* value,
                                size_t size) override;
  bool RemoveExtendedFileAttribute(const base::FilePath& path,
                                   const std::string& name) override;
  bool GetExtFileAttributes(const base::FilePath& path, int* flags) override;
  bool SetExtFileAttributes(const base::FilePath& path, int flags) override;
  bool HasNoDumpFileAttribute(const base::FilePath& path) override;
  bool Rename(const base::FilePath& from, const base::FilePath& to) override;
  base::Time GetCurrentTime() const override;
  bool Copy(const base::FilePath& from, const base::FilePath& to) override;
  bool StatVFS(const base::FilePath& path, struct statvfs* vfs) override;
  bool SameVFS(const base::FilePath& mnt_a,
               const base::FilePath& mnt_b) override;
  bool FindFilesystemDevice(const base::FilePath& filesystem,
                            std::string* device) override;
  bool ReportFilesystemDetails(const base::FilePath& filesystem,
                               const base::FilePath& logfile) override;
  bool SetupProcessKeyring() override;
  int GetDirectoryPolicyVersion(const base::FilePath& dir) const override;
  bool CheckFscryptKeyIoctlSupport() const override;
  dircrypto::KeyState GetDirCryptoKeyState(const base::FilePath& dir) override;
  bool SetDirCryptoKey(const base::FilePath& dir,
                       const dircrypto::KeyReference& key_reference) override;
  bool InvalidateDirCryptoKey(const dircrypto::KeyReference& key_reference,
                              const base::FilePath& shadow_root) override;
  bool ClearUserKeyring() override;
  bool FirmwareWriteProtected() override;
  bool SyncFile(const base::FilePath& path) override;
  bool SyncDirectory(const base::FilePath& path) override;
  void Sync() override;
  bool CreateSymbolicLink(const base::FilePath& path,
                          const base::FilePath& target) override;
  bool ReadLink(const base::FilePath& path, base::FilePath* target) override;
  bool SetFileTimes(const base::FilePath& path,
                    const struct timespec& atime,
                    const struct timespec& mtime,
                    bool follow_links) override;
  bool SendFile(int fd_to, int fd_from, off_t offset, size_t count) override;
  bool CreateSparseFile(const base::FilePath& path, int64_t size) override;
  bool GetBlkSize(const base::FilePath& device, uint64_t* size) override;
  bool DetachLoop(const base::FilePath& device_path) override;
  bool DiscardDevice(const base::FilePath& device) override;
  std::vector<LoopDevice> GetAttachedLoopDevices() override;
  bool FormatExt4(const base::FilePath& file,
                  const std::vector<std::string>& opts,
                  uint64_t blocks) override;
  bool Tune2Fs(const base::FilePath& file,
               const std::vector<std::string>& opts) override;
  bool ResizeFilesystem(const base::FilePath& file, uint64_t blocks) override;
  std::optional<std::string> GetSELinuxContextOfFD(int fd) override;
  bool SetSELinuxContext(const base::FilePath& path,
                         const std::string& context) override;
  bool RestoreSELinuxContexts(const base::FilePath& path,
                              bool recursive) override;
  bool SafeDirChmod(const base::FilePath& path, mode_t mode) override;
  bool SafeDirChown(const base::FilePath& path,
                    uid_t user_id,
                    gid_t group_id) override;
  bool SafeCreateDirAndSetOwnershipAndPermissions(const base::FilePath& path,
                                                  mode_t mode,
                                                  uid_t user_id,
                                                  gid_t gid) override;
  bool UdevAdmSettle(const base::FilePath& device_path,
                     bool wait_for_device) override;
  bool IsStatefulLogicalVolumeSupported() override;
  base::FilePath GetStatefulDevice() override;
  brillo::LoopDeviceManager* GetLoopDeviceManager() override;
  brillo::LogicalVolumeManager* GetLogicalVolumeManager() override;
  base::UnguessableToken CreateUnguessableToken() override;

 private:
  // `const` in order to be usable from const getters.
  bool GetArbitraryOutcome() const;

  bool WriteFileImpl(const base::FilePath& path,
                     brillo::Blob blob,
                     mode_t permissions);
  bool ReadFileImpl(const base::FilePath& path, brillo::Blob* blob);
  bool CreateDirectoryImpl(const base::FilePath& path,
                           mode_t permissions,
                           uid_t user_id,
                           gid_t gid);
  bool CopyImpl(const base::FilePath& from,
                const base::FilePath& to,
                bool copy_ownership_and_permissions);
  bool DeleteImpl(const base::FilePath& path, bool recursive);
  bool SetFileInfo(const base::FilePath& path,
                   bool expect_is_dir,
                   std::optional<mode_t> new_permissions,
                   std::optional<uid_t> new_user_id,
                   std::optional<gid_t> new_group_id);
  bool GetFileInfo(const base::FilePath& path,
                   mode_t* out_permissions,
                   uid_t* out_user_id,
                   gid_t* out_group_id) const;
  bool GetLoopDeviceMountsImpl(
      const base::FilePath& key_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts);

  FuzzedDataProvider& fuzzed_data_provider_;
  // A fast in-memory simulation of a file system, supporting basic operations.
  // The only reason it's used instead of delegating to `FakePlatform` is
  // performance.
  VirtualFs virtual_fs_;
  // TODO(b/254864841): Use fuzzed object instead of the fake, as the latter
  // always succeeds.
  brillo::fake::FakeLoopDeviceManager loop_device_manager_;
  testing::NiceMock<brillo::MockLogicalVolumeManager> logical_volume_manager_;
  // Pseudo-random engine for generating stable and predictable values. Note
  // that the default constructor uses hardcoded seed.
  std::mt19937_64 random_engine_64_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FUZZERS_FUZZED_PLATFORM_H_
