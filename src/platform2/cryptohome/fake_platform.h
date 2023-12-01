// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FAKE_PLATFORM_H_
#define CRYPTOHOME_FAKE_PLATFORM_H_

#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/unguessable_token.h>
#include <brillo/blkdev_utils/loop_device_fake.h>
#include <brillo/blkdev_utils/mock_lvm.h>
#include <brillo/secure_blob.h>

#include "cryptohome/fake_platform/fake_mount_mapper.h"
#include "cryptohome/platform.h"

namespace cryptohome {

class FakePlatform final : public Platform {
 public:
  FakePlatform();
  ~FakePlatform() override;

  // Prohibit copy/move/assignment.
  FakePlatform(const FakePlatform&) = delete;
  FakePlatform(const FakePlatform&&) = delete;
  FakePlatform& operator=(const FakePlatform&) = delete;
  FakePlatform& operator=(const FakePlatform&&) = delete;

  // Platform API

  FileEnumerator* GetFileEnumerator(const base::FilePath& path,
                                    bool recursive,
                                    int file_type) override;
  bool EnumerateDirectoryEntries(
      const base::FilePath& path,
      bool recursive,
      std::vector<base::FilePath>* ent_list) override;
  bool IsDirectoryEmpty(const base::FilePath& path) override;

  bool Rename(const base::FilePath& from, const base::FilePath& to) override;
  bool FindFilesystemDevice(const base::FilePath& filesystem,
                            std::string* device) override;
  bool Copy(const base::FilePath& from, const base::FilePath& to) override;
  bool StatVFS(const base::FilePath& path, struct statvfs* vfs) override;
  bool TouchFileDurable(const base::FilePath& path) override;
  bool DeleteFile(const base::FilePath& path) override;
  bool DeletePathRecursively(const base::FilePath& path) override;
  bool DeleteFileDurable(const base::FilePath& path) override;
  bool FileExists(const base::FilePath& path) const override;
  bool DirectoryExists(const base::FilePath& path) override;
  int Access(const base::FilePath& path, uint32_t flag) override;
  bool CreateDirectoryAndGetError(const base::FilePath& path,
                                  base::File::Error* error) override;
  bool CreateDirectory(const base::FilePath& path) override;
  bool CreateSparseFile(const base::FilePath& path, int64_t size) override;

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
  bool WriteFileAtomic(const base::FilePath& path,
                       const brillo::Blob& blob,
                       mode_t mode) override;
  bool WriteSecureBlobToFileAtomic(const base::FilePath& path,
                                   const brillo::SecureBlob& sblob,
                                   mode_t mode) override;
  bool WriteFileAtomicDurable(const base::FilePath& path,
                              const brillo::Blob& blob,
                              mode_t mode) override;
  bool WriteSecureBlobToFileAtomicDurable(const base::FilePath& path,
                                          const brillo::SecureBlob& sblob,
                                          mode_t mode) override;
  bool WriteStringToFile(const base::FilePath& path,
                         const std::string& str) override;
  bool WriteStringToFileAtomicDurable(const base::FilePath& path,
                                      const std::string& str,
                                      mode_t mode) override;
  bool WriteArrayToFile(const base::FilePath& path,
                        const char* data,
                        size_t size) override;

  FILE* OpenFile(const base::FilePath& path, const char* mode) override;
  bool CloseFile(FILE* file) override;

  bool GetFileSize(const base::FilePath& path, int64_t* size) override;

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
  bool GetQuotaProjectId(const base::FilePath& path,
                         int* project_id) const override;
  bool SetQuotaProjectId(const base::FilePath& path, int project_id) override;

  // TODO(chromium:1141301, dlunev): consider running under root to make the
  // following operate on FS, not on on fake state.
  bool GetOwnership(const base::FilePath& path,
                    uid_t* user_id,
                    gid_t* group_id,
                    bool follow_links) const override;
  bool SetOwnership(const base::FilePath& path,
                    uid_t user_id,
                    gid_t group_id,
                    bool follow_links) override;
  bool SetSELinuxContext(const base::FilePath& path,
                         const std::string& context) override;
  bool RestoreSELinuxContexts(const base::FilePath& path,
                              bool recursive) override;
  bool SafeDirChown(const base::FilePath& path,
                    uid_t user_id,
                    gid_t group_id) override;
  bool GetPermissions(const base::FilePath& path, mode_t* mode) const override;
  bool SetPermissions(const base::FilePath& path, mode_t mode) override;
  bool SafeDirChmod(const base::FilePath& path, mode_t mode) override;
  bool SafeCreateDirAndSetOwnershipAndPermissions(const base::FilePath& path,
                                                  mode_t mode,
                                                  uid_t user_id,
                                                  gid_t gid) override;
  int64_t AmountOfFreeDiskSpace(const base::FilePath& path) const override;

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
  bool GetLoopDeviceMounts(
      std::multimap<const base::FilePath, const base::FilePath>* mounts)
      override;
  bool GetMountsBySourcePrefix(
      const base::FilePath& from_prefix,
      std::multimap<const base::FilePath, const base::FilePath>* mounts)
      override;
  bool IsDirectoryMounted(const base::FilePath& directory) override;
  std::optional<std::vector<bool>> AreDirectoriesMounted(
      const std::vector<base::FilePath>& directories) override;
  base::FilePath GetStatefulDevice() override;
  brillo::LoopDeviceManager* GetLoopDeviceManager() override;
  brillo::LogicalVolumeManager* GetLogicalVolumeManager() override;
  brillo::MockLogicalVolumeManager* GetMockLogicalVolumeManager();
  base::UnguessableToken CreateUnguessableToken() override;

  // Test API

  // TODO(chromium:1141301, dlunev): this is a workaround of the fact that
  // libbrillo reads and caches system salt on it own and we are unable to
  // inject the tmpfs path to it.
  void SetSystemSaltForLibbrillo(const brillo::SecureBlob& salt);
  void RemoveSystemSaltForLibbrillo();

 private:
  class FakeExtendedAttributes final {
   public:
    FakeExtendedAttributes() = default;
    ~FakeExtendedAttributes() = default;
    bool Exists(const std::string& name) const;
    void List(std::vector<std::string>* attr_list) const;
    bool GetAsString(const std::string& name, std::string* value) const;
    bool Get(const std::string& name, char* value, ssize_t size) const;
    void Set(const std::string& name, const char* value, ssize_t size);
    void Remove(const std::string& name);

   private:
    std::unordered_map<std::string, std::vector<char>> xattrs_;
  };

  // Mappings for fake attributes of files. If you add a new mapping,
  // update `RemoveFakeEntries` and `RemoveFakeEntriesRecursive`.
  // Lock to protect the mappings. Should be held when reading or writing
  // them, because the calls into platform may happen concurrently.
  mutable base::Lock mappings_lock_;
  std::unordered_map<base::FilePath, FakeExtendedAttributes> xattrs_;
  // owners and perms are mutable due to const interface we need to abide.
  mutable std::unordered_map<base::FilePath, std::pair<uid_t, gid_t>>
      file_owners_;
  mutable std::unordered_map<base::FilePath, mode_t> file_mode_;
  mutable std::unordered_map<base::FilePath, int> file_flags_;
  mutable std::unordered_map<base::FilePath, int> project_ids_;

  base::FilePath tmpfs_rootfs_;
  std::unique_ptr<FakeMountMapper> fake_mount_mapper_;

  void RemoveFakeEntries(const base::FilePath& path);
  void RemoveFakeEntriesRecursive(const base::FilePath& path);
  base::FilePath ResolveMountPath(const base::FilePath& path) const;
  base::FilePath TestFilePath(const base::FilePath& path) const;
  base::FilePath StripTestFilePath(const base::FilePath& path) const;
  // TODO(dlunev): consider making IsLink a part of platform API.
  bool IsLink(const base::FilePath& path) const;

  Platform real_platform_;
  std::unique_ptr<brillo::fake::FakeLoopDeviceManager>
      fake_loop_device_manager_;

  std::unique_ptr<brillo::MockLogicalVolumeManager> mock_lvm_;

  std::string* old_salt_ = nullptr;

  // Pseudo-random engine for generating stable and predictable values. Note
  // that the default constructor uses hardcoded seed.
  std::mt19937_64 random_engine_64_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_FAKE_PLATFORM_H_
