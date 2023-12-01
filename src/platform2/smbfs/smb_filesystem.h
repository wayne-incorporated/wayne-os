// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SMB_FILESYSTEM_H_
#define SMBFS_SMB_FILESYSTEM_H_

#include <libsmbclient.h>
#include <sys/types.h>

#include <atomic>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/containers/lru_cache.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>

#include "smbfs/filesystem.h"
#include "smbfs/inode_map.h"
#include "smbfs/recursive_delete_operation.h"
#include "smbfs/smb_credential.h"

namespace smbfs {

class SambaInterface;

class SmbFilesystem : public Filesystem {
 public:
  // Delegate functions will always be called on the SmbFilesystem's constructor
  // thread. Any callback parameters must be invoked on the caller thread (read:
  // constructor thread).
  class Delegate {
   public:
    using RequestCredentialsCallback =
        base::OnceCallback<void(std::unique_ptr<SmbCredential> credentials)>;

    // Request username/password auth credentials for the share. Invoke
    // |callback| with the requested credentials, or with nullptr if no
    // credentials are provided (eg. if the user closes the request dialog).
    virtual void RequestCredentials(RequestCredentialsCallback callback) = 0;
  };

  struct Options {
    Options();
    ~Options();

    // Allow moves.
    Options(Options&&);
    Options& operator=(Options&&);

    std::string share_path;
    uid_t uid = 0;
    gid_t gid = 0;
    std::unique_ptr<SmbCredential> credentials;
    bool allow_ntlm = false;
    bool use_kerberos = false;
  };

  enum class ConnectError {
    kOk = 0,
    kNotFound,
    kAccessDenied,
    kSmb1Unsupported,
    kUnknownError,
  };

  SmbFilesystem(Delegate* delegate, Options options);

  SmbFilesystem() = delete;
  SmbFilesystem(const SmbFilesystem&) = delete;
  SmbFilesystem& operator=(const SmbFilesystem&) = delete;

  ~SmbFilesystem() override;

  base::WeakPtr<SmbFilesystem> GetWeakPtr();

  // Ensures that the SMB share can be connected to. Must NOT be called after
  // the filesystem is attached to a FUSE session.
  // Virtual for testing.
  virtual ConnectError EnsureConnected();

  // Sets the resolved IP address of the share host. |ip_address| is an IPv4
  // address in network byte order, or empty. If |ip_address| is empty, any
  // existing resolved address will be reset.
  // Virtual for testing.
  virtual void SetResolvedAddress(const std::vector<uint8_t>& ip_address);

  const std::string& resolved_share_path() const {
    return resolved_share_path_;
  }

  // Filesystem overrides.
  void StatFs(std::unique_ptr<StatFsRequest> request,
              fuse_ino_t inode) override;
  void Lookup(std::unique_ptr<EntryRequest> request,
              fuse_ino_t parent_inode,
              const std::string& name) override;
  void Forget(fuse_ino_t inode, uint64_t count) override;
  void GetAttr(std::unique_ptr<AttrRequest> request, fuse_ino_t inode) override;
  void SetAttr(std::unique_ptr<AttrRequest> request,
               fuse_ino_t inode,
               std::optional<uint64_t> file_handle,
               const struct stat& attr,
               int to_set) override;
  void Open(std::unique_ptr<OpenRequest> request,
            fuse_ino_t inode,
            int flags) override;
  void Create(std::unique_ptr<CreateRequest> request,
              fuse_ino_t parent_inode,
              const std::string& name,
              mode_t mode,
              int flags) override;
  void Read(std::unique_ptr<BufRequest> request,
            fuse_ino_t inode,
            uint64_t file_handle,
            size_t size,
            off_t offset) override;
  void Write(std::unique_ptr<WriteRequest> request,
             fuse_ino_t inode,
             uint64_t file_handle,
             const char* buf,
             size_t size,
             off_t offset) override;
  void Release(std::unique_ptr<SimpleRequest> request,
               fuse_ino_t inode,
               uint64_t file_handle) override;
  void Rename(std::unique_ptr<SimpleRequest> request,
              fuse_ino_t old_parent_inode,
              const std::string& old_name,
              fuse_ino_t new_parent_inode,
              const std::string& new_name) override;
  void Unlink(std::unique_ptr<SimpleRequest> request,
              fuse_ino_t parent_inode,
              const std::string& name) override;
  void OpenDir(std::unique_ptr<OpenRequest> request,
               fuse_ino_t inode,
               int flags) override;
  void ReadDir(std::unique_ptr<DirentryRequest> request,
               fuse_ino_t inode,
               uint64_t file_handle,
               off_t offset) override;
  void ReleaseDir(std::unique_ptr<SimpleRequest> request,
                  fuse_ino_t inode,
                  uint64_t file_handle) override;
  void MkDir(std::unique_ptr<EntryRequest> request,
             fuse_ino_t parent_inode,
             const std::string& name,
             mode_t mode) override;
  void RmDir(std::unique_ptr<SimpleRequest> request,
             fuse_ino_t parent_inode,
             const std::string& name) override;

  // mojom::SmbFs helpers.
  //
  // Recursively deletes |path| and all of its contents if it is a directory.
  // |path| is an absolute path from the root of the share (ie. it does not
  // include the smb://host portion). |callback| is called with the outcome of
  // the operation.
  void DeleteRecursively(const base::FilePath& path,
                         RecursiveDeleteOperation::CompletionCallback callback);

 protected:
  // Protected constructor for unit tests.
  SmbFilesystem(Delegate* delegate, const std::string& share_path);

  // Allow mock interface to be provided during tests.
  void SetSambaInterface(std::unique_ptr<SambaInterface> samba_interface);

 private:
  FRIEND_TEST(SmbFilesystemTest, MakeStatModeBits);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_NoRequest);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_RequestOnEPERM);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_RequestOnEACCES);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_NoDelegate);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_OnlyOneRequest);
  FRIEND_TEST(SmbFilesystemTest, MaybeUpdateCredentials_IgnoreEmptyResponse);

  // Cache stat information when listing directories to reduce unnecessary
  // network requests.
  struct StatCacheItem {
    struct stat inode_stat;
    base::Time expires_at;
  };

  // Filesystem implementations that execute on |samba_thread_|.
  void StatFsInternal(std::unique_ptr<StatFsRequest> request, fuse_ino_t inode);
  void LookupInternal(std::unique_ptr<EntryRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name);
  void ForgetInternal(fuse_ino_t inode, uint64_t count);
  void GetAttrInternal(std::unique_ptr<AttrRequest> request, fuse_ino_t inode);
  void SetAttrInternal(std::unique_ptr<AttrRequest> request,
                       fuse_ino_t inode,
                       std::optional<uint64_t> file_handle,
                       const struct stat& attr,
                       int to_set);
  int SetFileSizeInternal(const std::string& share_file_path,
                          std::optional<uint64_t> file_handle,
                          off_t size,
                          const struct stat& current_stat,
                          struct stat* reply_stat);
  int SetUtimesInternal(const std::string& share_file_path,
                        int to_set,
                        const struct timespec& atime,
                        const struct timespec& mtime,
                        const struct stat& current_stat,
                        struct stat* reply_stat);
  void OpenInternal(std::unique_ptr<OpenRequest> request,
                    fuse_ino_t inode,
                    int flags);
  void CreateInternal(std::unique_ptr<CreateRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name,
                      mode_t mode,
                      int flags);
  void ReadInternal(std::unique_ptr<BufRequest> request,
                    fuse_ino_t inode,
                    uint64_t file_handle,
                    size_t size,
                    off_t offset);
  void WriteInternal(std::unique_ptr<WriteRequest> request,
                     fuse_ino_t inode,
                     uint64_t file_handle,
                     const std::vector<char>& buf,
                     off_t offset);
  void ReleaseInternal(std::unique_ptr<SimpleRequest> request,
                       fuse_ino_t inode,
                       uint64_t file_handle);
  void RenameInternal(std::unique_ptr<SimpleRequest> request,
                      fuse_ino_t old_parent_inode,
                      const std::string& old_name,
                      fuse_ino_t new_parent_inode,
                      const std::string& new_name);
  void UnlinkInternal(std::unique_ptr<SimpleRequest> request,
                      fuse_ino_t parent_inode,
                      const std::string& name);
  void OpenDirInternal(std::unique_ptr<OpenRequest> request,
                       fuse_ino_t inode,
                       int flags);
  void ReadDirInternal(std::unique_ptr<DirentryRequest> request,
                       fuse_ino_t inode,
                       uint64_t file_handle,
                       off_t offset);
  void ReleaseDirInternal(std::unique_ptr<SimpleRequest> request,
                          fuse_ino_t inode,
                          uint64_t file_handle);
  void MkDirInternal(std::unique_ptr<EntryRequest> request,
                     fuse_ino_t parent_inode,
                     const std::string& name,
                     mode_t mode);
  void RmDirinternal(std::unique_ptr<SimpleRequest> request,
                     fuse_ino_t parent_inode,
                     const std::string& name);

  // mojom::SmbFs helpers that execute on |samba_thread_|.
  void DeleteRecursivelyInternal(
      const base::FilePath& path,
      RecursiveDeleteOperation::CompletionCallback callback);

  // Called on completion of the recursive delete.
  void OnDeleteRecursivelyDone(
      RecursiveDeleteOperation::CompletionCallback callback,
      mojom::DeleteRecursivelyError error);

  // Constructs a sanitised stat struct for sending as a response.
  struct stat MakeStat(ino_t inode, const struct stat& in_stat) const;

  // Clear / propagate permission bits appropriately (crbug.com/1063715).
  mode_t MakeStatModeBits(mode_t in_mode) const;

  // Constructs a share file path suitable for passing to libsmbclient from the
  // given absolute file path.
  std::string MakeShareFilePath(const base::FilePath& path) const;

  // Construct a share file path from the |inode|. |inode| must be a valid inode
  // number.
  std::string ShareFilePathFromInode(ino_t inode) const;

  // Registers an open file and returns a handle to that file. Always returns a
  // non-zero handle.
  uint64_t AddOpenFile(SMBCFILE* file);

  // Removes |handle| from the open file table.
  void RemoveOpenFile(uint64_t handle);

  // Returns the open file referred to by |handle|. Returns nullptr if |handle|
  // does not exist.
  SMBCFILE* LookupOpenFile(uint64_t handle) const;

  // Request credentials, if |error| is an auth failure, and the share has not
  // previously connected successfully.
  void MaybeUpdateCredentials(int error);

  // Request authentication credentials. Will do nothing is a request is
  // currently in progress.
  void RequestCredentialUpdate();

  // Callback handler for Delegate::RequestCredentials().
  void OnRequestCredentialsDone(std::unique_ptr<SmbCredential> credentials);

  // Cache a stat structure. |inode_stat.st_ino| is used as the key.
  void AddCachedInodeStat(const struct stat& inode_stat);

  // Remove the cached stat structure for |inode|.
  void EraseCachedInodeStat(ino_t inode);

  // Lookup the cached stat structure for |inode|. Returns true on cache hit or
  // false on a miss.
  bool GetCachedInodeStat(ino_t inode, struct stat* out_stat);

  Delegate* const delegate_ = nullptr;
  const std::string share_path_;
  const uid_t uid_ = 0;
  const gid_t gid_ = 0;
  const bool use_kerberos_ = false;
  base::Thread samba_thread_;
  InodeMap inode_map_{FUSE_ROOT_ID};

  // Origin/constructor thread task runner.
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_ =
      base::SingleThreadTaskRunner::GetCurrentDefault();

  std::unordered_map<uint64_t, SMBCFILE*> open_files_;
  uint64_t open_files_seq_ = 1;

  mutable base::Lock lock_;
  std::string resolved_share_path_ = share_path_;

  // Interface to libsmbclient.
  std::unique_ptr<SambaInterface> samba_impl_;

  // Cache stat information during ReadDir() to speed up subsequent access.
  base::HashingLRUCache<ino_t, StatCacheItem> stat_cache_;

  // Whether a successful connection to the SMB server has been made. Used to
  // determine whether or not to request auth credentials.
  // std::atomic<> load/store by default have acquire/release memory ordering.
  std::atomic<bool> connected_{false};
  // Flag to ensure only one credential request is active at a time.
  bool requesting_credentials_ = false;

  // At most one outstanding recursive delete operation can be in flight. This
  // object must live entirely on |samba_thread_|.
  std::unique_ptr<RecursiveDeleteOperation> recursive_delete_operation_;

  base::WeakPtrFactory<SmbFilesystem> weak_factory_{this};
};

std::ostream& operator<<(std::ostream& out, SmbFilesystem::ConnectError error);

}  // namespace smbfs

#endif  // SMBFS_SMB_FILESYSTEM_H_
