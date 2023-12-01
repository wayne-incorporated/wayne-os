// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/smb_filesystem.h"

#include <optional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>

#include "smbfs/samba_interface_impl.h"
#include "smbfs/util.h"

namespace smbfs {

namespace {

constexpr char kSambaThreadName[] = "smbfs-libsmb";
constexpr char kUrlPrefix[] = "smb://";

constexpr double kAttrTimeoutSeconds = 5.0;
constexpr mode_t kAllowedFileTypes = S_IFREG | S_IFDIR;
constexpr mode_t kFileModeMask = kAllowedFileTypes | 0770;

// Cache stat information for the latest 1024 directory entries retrieved.
constexpr int kStatCacheSize = 1024;
constexpr double kStatCacheTimeoutSeconds = kAttrTimeoutSeconds;

bool IsAllowedFileMode(mode_t mode) {
  return mode & kAllowedFileTypes;
}

}  // namespace

SmbFilesystem::Options::Options() = default;

SmbFilesystem::Options::~Options() = default;

SmbFilesystem::Options::Options(Options&&) = default;

SmbFilesystem::Options& SmbFilesystem::Options::operator=(Options&&) = default;

SmbFilesystem::SmbFilesystem(Delegate* delegate, Options options)
    : delegate_(delegate),
      share_path_(options.share_path),
      uid_(options.uid),
      gid_(options.gid),
      use_kerberos_(options.use_kerberos),
      samba_thread_(kSambaThreadName),
      stat_cache_(kStatCacheSize) {
  DCHECK(delegate_);

  // Ensure files are not owned by root.
  CHECK_GT(uid_, 0);
  CHECK_GT(gid_, 0);

  CHECK(!share_path_.empty());
  CHECK_NE(share_path_.back(), '/');

  samba_impl_ = std::make_unique<SambaInterfaceImpl>(
      std::move(options.credentials), options.allow_ntlm);

  CHECK(samba_thread_.Start());
}

SmbFilesystem::SmbFilesystem(Delegate* delegate, const std::string& share_path)
    : delegate_(delegate),
      share_path_(share_path),
      samba_thread_(kSambaThreadName),
      stat_cache_(kStatCacheSize) {
  DCHECK(delegate_);
}

SmbFilesystem::~SmbFilesystem() {
  if (samba_impl_) {
    // Stop the Samba processing thread before destroying the context to avoid a
    // UAF on the context.
    samba_thread_.Stop();
  }
}

base::WeakPtr<SmbFilesystem> SmbFilesystem::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

void SmbFilesystem::SetSambaInterface(
    std::unique_ptr<SambaInterface> samba_interface) {
  samba_impl_ = std::move(samba_interface);
}

SmbFilesystem::ConnectError SmbFilesystem::EnsureConnected() {
  SMBCFILE* dir = nullptr;
  int err = samba_impl_->OpenDirectory(resolved_share_path_, &dir);
  if (err) {
    LOG(INFO) << "EnsureConnected OpenDirectory failed: " << err;
    switch (err) {
      case EPERM:
      case EACCES:
        return ConnectError::kAccessDenied;
      case ENODEV:
      case ENOENT:
      case ETIMEDOUT:
      // This means unable to resolve host, in some, but not necessarily all
      // cases.
      case EINVAL:
      // Host unreachable.
      case EHOSTUNREACH:
      // Host not listening on SMB port.
      case ECONNREFUSED:
        return ConnectError::kNotFound;
      case ECONNABORTED:
        return ConnectError::kSmb1Unsupported;
      default:
        LOG(WARNING) << "Unexpected error code " << err << ": "
                     << base::safe_strerror(err);
        return ConnectError::kUnknownError;
    }
  }

  connected_ = true;

  err = samba_impl_->CloseDirectory(dir);
  LOG_IF(WARNING, err) << "CloseDirectory during EnsureConnected failed: "
                       << base::safe_strerror(err);

  return ConnectError::kOk;
}

void SmbFilesystem::SetResolvedAddress(const std::vector<uint8_t>& ip_address) {
  base::AutoLock l(lock_);

  if (ip_address.empty()) {
    resolved_share_path_ = share_path_;
    return;
  } else if (ip_address.size() != 4) {
    // TODO(crbug.com/1051291): Support IPv6.
    LOG(ERROR) << "Invalid IP address";
    return;
  }

  std::string address_str = IpAddressToString(ip_address);
  DCHECK(!address_str.empty());

  const base::StringPiece prefix(kUrlPrefix);
  DCHECK(base::StartsWith(share_path_, prefix, base::CompareCase::SENSITIVE));
  std::string::size_type host_end = share_path_.find('/', prefix.size());
  DCHECK_NE(host_end, std::string::npos);
  resolved_share_path_ =
      std::string(prefix) + address_str + share_path_.substr(host_end);
}

struct stat SmbFilesystem::MakeStat(ino_t inode,
                                    const struct stat& in_stat) const {
  struct stat stat = {0};
  stat.st_ino = inode;
  stat.st_mode = MakeStatModeBits(in_stat.st_mode);
  stat.st_uid = uid_;
  stat.st_gid = gid_;
  stat.st_nlink = 1;
  stat.st_size = in_stat.st_size;
  stat.st_atim = in_stat.st_atim;
  stat.st_ctim = in_stat.st_ctim;
  stat.st_mtim = in_stat.st_mtim;
  return stat;
}

mode_t SmbFilesystem::MakeStatModeBits(mode_t in_mode) const {
  mode_t mode = in_mode;

  // Clear any "other" permission bits.
  mode &= kFileModeMask;

  // If the entry is a directory, it must have the execute bit set.
  if (in_mode & S_IFDIR) {
    mode |= S_IXUSR;
  } else {
    mode &= ~S_IXUSR;
  }

  // Propagate user bits to group bits.
  mode &= ~S_IRWXG;
  if (mode & S_IRUSR) {
    mode |= S_IRGRP;
  }
  if (mode & S_IWUSR) {
    mode |= S_IWGRP;
  }
  if (mode & S_IXUSR) {
    mode |= S_IXGRP;
  }

  return mode;
}

std::string SmbFilesystem::MakeShareFilePath(const base::FilePath& path) const {
  std::string base_share_path;
  {
    base::AutoLock l(lock_);
    DCHECK(!resolved_share_path_.empty());
    base_share_path = resolved_share_path_;
  }

  if (path == base::FilePath("/")) {
    return base_share_path;
  }

  // Paths are constructed and not passed directly over FUSE. Therefore, these
  // two properties should always hold.
  DCHECK(path.IsAbsolute());
  DCHECK(!path.EndsWithSeparator());
  return base_share_path + path.value();
}

std::string SmbFilesystem::ShareFilePathFromInode(ino_t inode) const {
  const base::FilePath file_path = inode_map_.GetPath(inode);
  CHECK(!file_path.empty()) << "Path lookup for invalid inode: " << inode;
  return MakeShareFilePath(file_path);
}

uint64_t SmbFilesystem::AddOpenFile(SMBCFILE* file) {
  uint64_t handle = open_files_seq_++;
  // Disallow wrap around.
  CHECK(handle);
  open_files_[handle] = file;
  return handle;
}

void SmbFilesystem::RemoveOpenFile(uint64_t handle) {
  auto it = open_files_.find(handle);
  if (it == open_files_.end()) {
    NOTREACHED() << "File handle not found";
    return;
  }
  open_files_.erase(it);
}

SMBCFILE* SmbFilesystem::LookupOpenFile(uint64_t handle) const {
  const auto it = open_files_.find(handle);
  if (it == open_files_.end()) {
    return nullptr;
  }
  return it->second;
}

void SmbFilesystem::MaybeUpdateCredentials(int error) {
  if (use_kerberos_) {
    // If Kerberos is being used, it is assumed a valid user/workgroup has
    // already been provided, and password is always ignored.
    return;
  } else if (connected_) {
    // If a connection has already been made successfully, assume the
    // existing credentials are correct.
    return;
  }

  if (error == EPERM || error == EACCES) {
    // Delegate calls must always be made on the constructor thread.
    main_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&SmbFilesystem::RequestCredentialUpdate,
                                  base::Unretained(this)));
  }
}

void SmbFilesystem::RequestCredentialUpdate() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (requesting_credentials_) {
    // Do nothing if a credential request is already in progress.
    return;
  }

  requesting_credentials_ = true;
  delegate_->RequestCredentials(
      base::BindOnce(&SmbFilesystem::OnRequestCredentialsDone, GetWeakPtr()));
}

void SmbFilesystem::OnRequestCredentialsDone(
    std::unique_ptr<SmbCredential> credentials) {
  requesting_credentials_ = false;
  if (!credentials) {
    return;
  }

  samba_impl_->UpdateCredentials(std::move(credentials));
}

void SmbFilesystem::StatFs(std::unique_ptr<StatFsRequest> request,
                           fuse_ino_t inode) {
  VLOG(2) << "StatFs inode: " << inode;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::StatFsInternal, base::Unretained(this),
                     std::move(request), inode));
}

void SmbFilesystem::StatFsInternal(std::unique_ptr<StatFsRequest> request,
                                   fuse_ino_t inode) {
  VLOG(2) << "StatFsInternal inode: " << inode;

  if (request->IsInterrupted()) {
    return;
  }

  std::string share_file_path = ShareFilePathFromInode(inode);
  VLOG(2) << "StatFsInternal inode: " << inode
          << " -> path: " << share_file_path;

  struct statvfs smb_statvfs = {0};
  int error = samba_impl_->StatVfs(share_file_path, &smb_statvfs);
  if (error) {
    VLOG(1) << "StatVfs path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyStatFs(smb_statvfs);
}

void SmbFilesystem::Lookup(std::unique_ptr<EntryRequest> request,
                           fuse_ino_t parent_inode,
                           const std::string& name) {
  VLOG(2) << "Lookup parent_inode: " << parent_inode << " name: " << name;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::LookupInternal, base::Unretained(this),
                     std::move(request), parent_inode, name));
}

void SmbFilesystem::LookupInternal(std::unique_ptr<EntryRequest> request,
                                   fuse_ino_t parent_inode,
                                   const std::string& name) {
  VLOG(2) << "LookupInternal parent_inode: " << parent_inode
          << " name: " << name;
  if (request->IsInterrupted()) {
    return;
  }

  const base::FilePath parent_path = inode_map_.GetPath(parent_inode);
  CHECK(!parent_path.empty())
      << "Lookup on invalid parent inode: " << parent_inode;
  const base::FilePath file_path = parent_path.Append(name);
  const std::string share_file_path = MakeShareFilePath(file_path);
  VLOG(2) << "LookupInternal parent_inode: " << parent_inode
          << " name: " << name << " -> path: " << share_file_path;

  ino_t inode = inode_map_.IncInodeRef(file_path);
  struct stat smb_stat = {0};
  if (!GetCachedInodeStat(inode, &smb_stat)) {
    int error = samba_impl_->Stat(share_file_path, &smb_stat);
    if (error) {
      VLOG(1) << "Stat path: " << share_file_path
              << " failed: " << base::safe_strerror(error);
      request->ReplyError(error);
      inode_map_.Forget(inode, 1);
      return;
    } else if (!IsAllowedFileMode(smb_stat.st_mode)) {
      VLOG(1) << "Disallowed file mode " << smb_stat.st_mode << " for path "
              << share_file_path;
      request->ReplyError(EACCES);
      inode_map_.Forget(inode, 1);
      return;
    }
  }

  struct stat entry_stat = MakeStat(inode, smb_stat);
  fuse_entry_param entry = {0};
  entry.ino = inode;
  entry.generation = 1;
  entry.attr = entry_stat;
  entry.attr_timeout = kAttrTimeoutSeconds;
  entry.entry_timeout = kAttrTimeoutSeconds;
  request->ReplyEntry(entry);
}

void SmbFilesystem::Forget(fuse_ino_t inode, uint64_t count) {
  VLOG(2) << "Forget inode: " << inode << " count: " << count;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&SmbFilesystem::ForgetInternal,
                                base::Unretained(this), inode, count));
}

void SmbFilesystem::ForgetInternal(fuse_ino_t inode, uint64_t count) {
  VLOG(2) << "ForgetInternal inode: " << inode << " count: " << count;
  if (inode_map_.Forget(inode, count)) {
    // The inode was removed, invalidate any cached stat information.
    EraseCachedInodeStat(inode);
  }
}

void SmbFilesystem::GetAttr(std::unique_ptr<AttrRequest> request,
                            fuse_ino_t inode) {
  VLOG(2) << "GetAttr inode: " << inode;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::GetAttrInternal, base::Unretained(this),
                     std::move(request), inode));
}

void SmbFilesystem::GetAttrInternal(std::unique_ptr<AttrRequest> request,
                                    fuse_ino_t inode) {
  VLOG(2) << "GetAttrInternal inode: " << inode;
  if (request->IsInterrupted()) {
    return;
  }

  struct stat smb_stat = {0};
  const std::string share_file_path = ShareFilePathFromInode(inode);
  VLOG(2) << "GetAttrInternal inode: " << inode
          << " -> path: " << share_file_path;

  if (!GetCachedInodeStat(inode, &smb_stat)) {
    int error = samba_impl_->Stat(share_file_path, &smb_stat);
    if (error) {
      VLOG(1) << "Stat path: " << share_file_path
              << " failed: " << base::safe_strerror(error);

      if (inode == FUSE_ROOT_ID) {
        MaybeUpdateCredentials(error);
      }

      request->ReplyError(error);
      return;
    }
  }

  if (!IsAllowedFileMode(smb_stat.st_mode)) {
    VLOG(1) << "Disallowed file mode " << smb_stat.st_mode << " for path "
            << share_file_path;
    request->ReplyError(EACCES);
    return;
  }

  connected_ = true;
  struct stat reply_stat = MakeStat(inode, smb_stat);
  request->ReplyAttr(reply_stat, kAttrTimeoutSeconds);
}

void SmbFilesystem::SetAttr(std::unique_ptr<AttrRequest> request,
                            fuse_ino_t inode,
                            std::optional<uint64_t> file_handle,
                            const struct stat& attr,
                            int to_set) {
  VLOG(2) << "SetAttr inode: " << inode << " to_set: " << to_set;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&SmbFilesystem::SetAttrInternal,
                                base::Unretained(this), std::move(request),
                                inode, std::move(file_handle), attr, to_set));
}

void SmbFilesystem::SetAttrInternal(std::unique_ptr<AttrRequest> request,
                                    fuse_ino_t inode,
                                    std::optional<uint64_t> file_handle,
                                    const struct stat& attr,
                                    int to_set) {
  VLOG(2) << "SetAttrInternal inode: " << inode << " to_set: " << to_set;
  if (request->IsInterrupted()) {
    return;
  }

  // Currently, only setting size (ie. O_TRUC, ftruncate()) or times (ie.
  // utime(), utimensat()) is supported.
  const int kSupportedAttrs =
      FUSE_SET_ATTR_SIZE | FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME;
  if (to_set & ~kSupportedAttrs) {
    LOG(WARNING) << "Unsupported |to_set| flags on setattr: " << to_set;
    request->ReplyError(ENOTSUP);
    return;
  }
  if (!to_set) {
    VLOG(1) << "No supported |to_set| flags set on setattr: " << to_set;
    request->ReplyError(EINVAL);
    return;
  }

  const std::string share_file_path = ShareFilePathFromInode(inode);
  VLOG(2) << "SetAttrInternal inode: " << inode
          << " -> path: " << share_file_path;

  struct stat smb_stat = {0};
  int error = samba_impl_->Stat(share_file_path, &smb_stat);
  if (error) {
    VLOG(1) << "Stat path (during SetAttrInternal): " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }
  struct stat reply_stat = MakeStat(inode, smb_stat);

  // SetAttrInternal supports changing multiple attributes simultaneously but
  // this is not atomic: all changes must succeed for the request to succeed but
  // a partial failure will not be unapplied.
  if (to_set & FUSE_SET_ATTR_SIZE) {
    error = SetFileSizeInternal(share_file_path, file_handle, attr.st_size,
                                smb_stat, &reply_stat);
    if (error) {
      request->ReplyError(error);
      return;
    }
  }

  if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
    error = SetUtimesInternal(share_file_path, to_set, attr.st_atim,
                              attr.st_mtim, smb_stat, &reply_stat);
    if (error) {
      request->ReplyError(error);
      return;
    }
  }

  // Modifying the attributes invalidates any cached inode we have.
  EraseCachedInodeStat(inode);

  request->ReplyAttr(reply_stat, kAttrTimeoutSeconds);
}

int SmbFilesystem::SetFileSizeInternal(const std::string& share_file_path,
                                       std::optional<uint64_t> file_handle,
                                       off_t size,
                                       const struct stat& current_stat,
                                       struct stat* reply_stat) {
  VLOG(2) << "SetFileSizeInternal path: " << share_file_path
          << " size: " << size;
  DCHECK(reply_stat);

  if (current_stat.st_mode & S_IFDIR) {
    return EISDIR;
  } else if (!(current_stat.st_mode & S_IFREG)) {
    VLOG(1) << "Disallowed file mode " << current_stat.st_mode << " for path "
            << share_file_path;
    return EACCES;
  }

  SMBCFILE* file = nullptr;
  int error = 0;
  base::ScopedClosureRunner file_closer;
  if (file_handle) {
    file = LookupOpenFile(*file_handle);
    if (!file) {
      VLOG(1) << "Bad file handle";
      return EBADF;
    }
  } else {
    error = samba_impl_->OpenFile(share_file_path, O_WRONLY, 0, &file);
    if (error) {
      VLOG(1) << "OpenFile path: " << share_file_path
              << " failed: " << base::safe_strerror(error);
      return error;
    }

    file_closer.ReplaceClosure(base::BindOnce(
        [](SambaInterface* samba_impl, SMBCFILE* file) {
          int error = samba_impl->CloseFile(file);
          if (error) {
            LOG(ERROR)
                << "CloseFile failed on temporary SetFileSizeInternal file: "
                << base::safe_strerror(error);
          }
        },
        samba_impl_.get(), file));
  }

  error = samba_impl_->TruncateFile(file, size);
  if (error) {
    VLOG(1) << "TruncateFile size: " << size
            << " failed: " << base::safe_strerror(error);
    return error;
  }
  reply_stat->st_size = size;

  return 0;
}

int SmbFilesystem::SetUtimesInternal(const std::string& share_file_path,
                                     int to_set,
                                     const struct timespec& atime,
                                     const struct timespec& mtime,
                                     const struct stat& current_stat,
                                     struct stat* reply_stat) {
  VLOG(2) << "SetUtimesInternal path: " << share_file_path;
  DCHECK(to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME));
  DCHECK(reply_stat);

  struct timespec requested_atime = current_stat.st_atim;
  struct timespec requested_mtime = current_stat.st_mtim;

  if (to_set & FUSE_SET_ATTR_ATIME) {
    requested_atime = atime;
  }
  if (to_set & FUSE_SET_ATTR_MTIME) {
    requested_mtime = mtime;
  }

  int error =
      samba_impl_->SetUtimes(share_file_path, requested_atime, requested_mtime);
  if (error) {
    VLOG(1) << "SetUtimes path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    return error;
  }

  reply_stat->st_atim = requested_atime;
  reply_stat->st_mtim = requested_mtime;

  return 0;
}

void SmbFilesystem::Open(std::unique_ptr<OpenRequest> request,
                         fuse_ino_t inode,
                         int flags) {
  VLOG(2) << "Open inode: " << inode << " flags: " << flags;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::OpenInternal, base::Unretained(this),
                     std::move(request), inode, flags));
}

void SmbFilesystem::OpenInternal(std::unique_ptr<OpenRequest> request,
                                 fuse_ino_t inode,
                                 int flags) {
  VLOG(2) << "OpenInternal inode: " << inode << " flags: " << flags;
  if (request->IsInterrupted()) {
    return;
  }

  if (inode == FUSE_ROOT_ID) {
    request->ReplyError(EISDIR);
    return;
  }

  const std::string share_file_path = ShareFilePathFromInode(inode);
  VLOG(2) << "OpenInternal inode: " << inode << " -> path: " << share_file_path;

  SMBCFILE* file = nullptr;
  int error = samba_impl_->OpenFile(share_file_path, flags, 0, &file);
  if (error) {
    VLOG(1) << "OpenFile path " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyOpen(AddOpenFile(file));
}

void SmbFilesystem::Create(std::unique_ptr<CreateRequest> request,
                           fuse_ino_t parent_inode,
                           const std::string& name,
                           mode_t mode,
                           int flags) {
  VLOG(2) << "Create parent_inode: " << parent_inode << " name: " << name
          << " mode: " << mode << " flags: " << flags;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::CreateInternal, base::Unretained(this),
                     std::move(request), parent_inode, name, mode, flags));
}

void SmbFilesystem::CreateInternal(std::unique_ptr<CreateRequest> request,
                                   fuse_ino_t parent_inode,
                                   const std::string& name,
                                   mode_t mode,
                                   int flags) {
  VLOG(2) << "CreateInternal parent_inode: " << parent_inode
          << " name: " << name << " mode: " << mode << " flags: " << flags;
  if (request->IsInterrupted()) {
    return;
  }

  flags |= O_CREAT;
  mode &= 0777;

  const base::FilePath parent_path = inode_map_.GetPath(parent_inode);
  CHECK(!parent_path.empty())
      << "Lookup on invalid parent inode: " << parent_inode;
  const base::FilePath file_path = parent_path.Append(name);
  const std::string share_file_path = MakeShareFilePath(file_path);
  VLOG(2) << "CreateInternal parent inode: " << parent_inode
          << " name: " << name << " -> path: " << share_file_path;

  // NOTE: |mode| appears to be ignored by libsmbclient.
  SMBCFILE* file = nullptr;
  int error = samba_impl_->OpenFile(share_file_path, flags, mode, &file);
  if (error) {
    VLOG(1) << "OpenFile path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  uint64_t handle = AddOpenFile(file);

  ino_t inode = inode_map_.IncInodeRef(file_path);
  struct stat entry_stat = MakeStat(inode, {0});
  entry_stat.st_mode = S_IFREG | mode;
  fuse_entry_param entry = {0};
  entry.ino = inode;
  entry.generation = 1;
  entry.attr = entry_stat;
  // Force readers to see coherent user / group permission bits by not caching
  // stat structure.
  entry.attr_timeout = 0;
  entry.entry_timeout = kAttrTimeoutSeconds;
  request->ReplyCreate(entry, handle);
}

void SmbFilesystem::Read(std::unique_ptr<BufRequest> request,
                         fuse_ino_t inode,
                         uint64_t file_handle,
                         size_t size,
                         off_t offset) {
  VLOG(2) << "Read inode: " << inode << " size: " << size
          << " offset: " << offset;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::ReadInternal, base::Unretained(this),
                     std::move(request), inode, file_handle, size, offset));
}

void SmbFilesystem::ReadInternal(std::unique_ptr<BufRequest> request,
                                 fuse_ino_t inode,
                                 uint64_t file_handle,
                                 size_t size,
                                 off_t offset) {
  VLOG(2) << "ReadInternal inode: " << inode << " size: " << size
          << " offset: " << offset;
  if (request->IsInterrupted()) {
    return;
  }

  SMBCFILE* file = LookupOpenFile(file_handle);
  if (!file) {
    VLOG(1) << "Bad file handle";
    request->ReplyError(EBADF);
    return;
  }

  int error = samba_impl_->SeekFile(file, offset, SEEK_SET);
  if (error) {
    VLOG(1) << "SeekFile path: " << ShareFilePathFromInode(inode)
            << ", offset: " << offset
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  std::vector<char> buf(size);
  size_t bytes_read = 0;
  error = samba_impl_->ReadFile(file, buf.data(), size, &bytes_read);
  if (error) {
    VLOG(1) << "ReadFile path: " << ShareFilePathFromInode(inode)
            << " offset: " << offset << ", size: " << size
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyBuf(buf.data(), bytes_read);
}

void SmbFilesystem::Write(std::unique_ptr<WriteRequest> request,
                          fuse_ino_t inode,
                          uint64_t file_handle,
                          const char* buf,
                          size_t size,
                          off_t offset) {
  VLOG(2) << "Write inode: " << inode << "file_handle: " << file_handle
          << " size: " << size << " offset: " << offset;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::WriteInternal, base::Unretained(this),
                     std::move(request), inode, file_handle,
                     std::vector<char>(buf, buf + size), offset));
}

void SmbFilesystem::WriteInternal(std::unique_ptr<WriteRequest> request,
                                  fuse_ino_t inode,
                                  uint64_t file_handle,
                                  const std::vector<char>& buf,
                                  off_t offset) {
  VLOG(2) << "WriteInternal inode: " << inode << " file_handle: " << file_handle
          << " offset: " << offset;
  if (request->IsInterrupted()) {
    return;
  }

  SMBCFILE* file = LookupOpenFile(file_handle);
  if (!file) {
    VLOG(1) << "Bad file handle";
    request->ReplyError(EBADF);
    return;
  }

  int error = samba_impl_->SeekFile(file, offset, SEEK_SET);
  if (error) {
    VLOG(1) << "SeekFile path: " << ShareFilePathFromInode(inode)
            << ", offset: " << offset
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  size_t bytes_written = 0;
  error = samba_impl_->WriteFile(file, buf.data(), buf.size(), &bytes_written);
  if (error) {
    VLOG(1) << "WriteFile path: " << ShareFilePathFromInode(inode)
            << " offset: " << offset << ", size: " << buf.size()
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  // Modifying the file invalidates any cached inode we have.
  EraseCachedInodeStat(inode);

  request->ReplyWrite(bytes_written);
}

void SmbFilesystem::Release(std::unique_ptr<SimpleRequest> request,
                            fuse_ino_t inode,
                            uint64_t file_handle) {
  VLOG(2) << "Release inode: " << inode << " file_handle: " << file_handle;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::ReleaseInternal, base::Unretained(this),
                     std::move(request), inode, file_handle));
}

void SmbFilesystem::ReleaseInternal(std::unique_ptr<SimpleRequest> request,
                                    fuse_ino_t inode,
                                    uint64_t file_handle) {
  VLOG(2) << "ReleaseInternal inode: " << inode
          << " file_handle: " << file_handle;
  if (request->IsInterrupted()) {
    return;
  }

  SMBCFILE* file = LookupOpenFile(file_handle);
  if (!file) {
    VLOG(1) << "Bad file handle";
    request->ReplyError(EBADF);
    return;
  }

  int error = samba_impl_->CloseFile(file);
  if (error) {
    request->ReplyError(error);
    return;
  }

  RemoveOpenFile(file_handle);
  request->ReplyOk();
}

void SmbFilesystem::Rename(std::unique_ptr<SimpleRequest> request,
                           fuse_ino_t old_parent_inode,
                           const std::string& old_name,
                           fuse_ino_t new_parent_inode,
                           const std::string& new_name) {
  VLOG(2) << "Rename old_parent_inode: " << old_parent_inode
          << " old_name: " << old_name
          << " new_parent_inode: " << new_parent_inode
          << " new_name: " << new_name;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::RenameInternal, base::Unretained(this),
                     std::move(request), old_parent_inode, old_name,
                     new_parent_inode, new_name));
}

void SmbFilesystem::RenameInternal(std::unique_ptr<SimpleRequest> request,
                                   fuse_ino_t old_parent_inode,
                                   const std::string& old_name,
                                   fuse_ino_t new_parent_inode,
                                   const std::string& new_name) {
  VLOG(2) << "RenameInternal old_parent_inode: " << old_parent_inode
          << " old_name: " << old_name
          << " new_parent_inode: " << new_parent_inode
          << " new_name: " << new_name;
  if (request->IsInterrupted()) {
    return;
  }

  const base::FilePath old_parent_path = inode_map_.GetPath(old_parent_inode);
  CHECK(!old_parent_path.empty())
      << "Lookup on invalid old parent inode: " << old_parent_inode;
  const base::FilePath new_parent_path = inode_map_.GetPath(new_parent_inode);
  CHECK(!new_parent_path.empty())
      << "Lookup on invalid new parent inode: " << new_parent_inode;

  const base::FilePath old_path = old_parent_path.Append(old_name);
  const std::string old_share_path = MakeShareFilePath(old_path);
  const base::FilePath new_path = new_parent_path.Append(new_name);
  const std::string new_share_path = MakeShareFilePath(new_path);
  VLOG(2) << "RenameInternal old path: " << old_share_path
          << " new path: " << new_share_path;

  if (inode_map_.PathExists(new_path)) {
    // This is posix-violating behaviour since rename() is supposed to replace
    // new_path if it exists. However, this is currently complicated by the need
    // to maintain a consistent mapping between inodes and paths.
    VLOG(1) << "Rename failed since new path already exists, new_path: "
            << new_share_path;
    request->ReplyError(EEXIST);
    return;
  }

  int error = samba_impl_->Rename(old_share_path, new_share_path);
  if (error) {
    VLOG(1) << "Rename old_path: " << old_share_path
            << " new_path: " << new_share_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  // A rename only moves the directory entry and doesn't change the underlying
  // inode. So update our synthesized inode to point to the new location. This
  // is safe since there's no support for hardlinks, and we have a 1:1 mapping
  // between path and inode.
  ino_t inode = inode_map_.IncInodeRef(old_path);
  inode_map_.UpdatePath(inode, new_path);
  // Unref the inode so we don't go out of sync with the kernel's refcount.
  inode_map_.Forget(inode, 1);

  // The SMB server might update attributes for the destination path (eg.
  // modification time). Invalidate our cached stat and force a fetch from the
  // server.
  EraseCachedInodeStat(inode);

  request->ReplyOk();
}

void SmbFilesystem::Unlink(std::unique_ptr<SimpleRequest> request,
                           fuse_ino_t parent_inode,
                           const std::string& name) {
  VLOG(2) << "Unlink parent_inode: " << parent_inode << " name: " << name;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::UnlinkInternal, base::Unretained(this),
                     std::move(request), parent_inode, name));
}

void SmbFilesystem::UnlinkInternal(std::unique_ptr<SimpleRequest> request,
                                   fuse_ino_t parent_inode,
                                   const std::string& name) {
  VLOG(2) << "UnlinkInternal parent_inode: " << parent_inode
          << " name: " << name;
  if (request->IsInterrupted()) {
    return;
  }

  const base::FilePath parent_path = inode_map_.GetPath(parent_inode);
  CHECK(!parent_path.empty())
      << "Lookup on invalid parent inode: " << parent_inode;
  const std::string share_file_path =
      MakeShareFilePath(parent_path.Append(name));
  VLOG(2) << "UnlinkInternal parent_inode: " << parent_inode
          << " name: " << name << " -> path: " << share_file_path;

  int error = samba_impl_->UnlinkFile(share_file_path);
  if (error) {
    VLOG(1) << "Unlink path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyOk();
}

void SmbFilesystem::OpenDir(std::unique_ptr<OpenRequest> request,
                            fuse_ino_t inode,
                            int flags) {
  VLOG(2) << "OpenDir inode: " << inode << " flags: " << flags;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::OpenDirInternal, base::Unretained(this),
                     std::move(request), inode, flags));
}

void SmbFilesystem::OpenDirInternal(std::unique_ptr<OpenRequest> request,
                                    fuse_ino_t inode,
                                    int flags) {
  VLOG(2) << "OpenDirInternal inode: " << inode << " flags: " << flags;
  if (request->IsInterrupted()) {
    return;
  }

  if ((flags & O_ACCMODE) != O_RDONLY) {
    VLOG(1) << "Directories can only be opened read-only, requested flags: "
            << flags;
    request->ReplyError(EACCES);
    return;
  }

  const std::string share_dir_path = ShareFilePathFromInode(inode);
  VLOG(2) << "OpenDirInternal inode: " << inode << " flags: " << flags
          << " -> path: " << share_dir_path;

  SMBCFILE* dir = nullptr;
  int error = samba_impl_->OpenDirectory(share_dir_path, &dir);
  if (error) {
    VLOG(1) << "OpenDirectory path: " << share_dir_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyOpen(AddOpenFile(dir));
}

void SmbFilesystem::ReadDir(std::unique_ptr<DirentryRequest> request,
                            fuse_ino_t inode,
                            uint64_t file_handle,
                            off_t offset) {
  VLOG(2) << "ReadDir inode: " << inode << " offset: " << offset;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::ReadDirInternal, base::Unretained(this),
                     std::move(request), inode, file_handle, offset));
}

void SmbFilesystem::ReadDirInternal(std::unique_ptr<DirentryRequest> request,
                                    fuse_ino_t inode,
                                    uint64_t file_handle,
                                    off_t offset) {
  VLOG(2) << "ReadDirInternal inode: " << inode << " offset: " << offset;
  if (request->IsInterrupted()) {
    return;
  }

  SMBCFILE* dir = LookupOpenFile(file_handle);
  if (!dir) {
    VLOG(1) << "Bad file handle";
    request->ReplyError(EBADF);
    return;
  }
  const base::FilePath dir_path = inode_map_.GetPath(inode);
  CHECK(!dir_path.empty()) << "Inode not found: " << inode;
  VLOG(2) << "ReadDirInternal inode: " << inode << " offset: " << offset
          << " -> path: " << dir_path;

  int error = samba_impl_->SeekDirectory(dir, offset);
  if (error) {
    VLOG(1) << "SeekDirectory path: " << dir_path.value()
            << ", offset: " << offset
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  while (true) {
    const struct libsmb_file_info* dirent_info = nullptr;
    struct stat inode_stat = {0};

    error = samba_impl_->ReadDirectory(dir, &dirent_info, &inode_stat);
    if (error) {
      VLOG(1) << "ReadDirectory path: " << dir_path.value()
              << " failed: " << base::safe_strerror(error);
      request->ReplyError(error);
      return;
    }
    if (!dirent_info) {
      // EOF.
      break;
    }
    off_t next_offset = 0;
    error = samba_impl_->TellDirectory(dir, &next_offset);
    if (error) {
      VLOG(1) << "TellDirectory path: " << dir_path.value()
              << " failed: " << base::safe_strerror(error);
      request->ReplyError(error);
      return;
    }

    base::StringPiece filename(dirent_info->name);
    if (filename == "." || filename == "..") {
      // Ignore . and .. since FUSE already takes care of these.
      continue;
    }
    CHECK(!filename.empty());
    CHECK_EQ(filename.find("/"), base::StringPiece::npos);

    // Ensure mode bits are appropriately cleaned and propagated.
    inode_stat.st_mode = MakeStatModeBits(inode_stat.st_mode);

    const base::FilePath entry_path = dir_path.Append(filename);
    ino_t entry_inode = inode_map_.GetWeakInode(entry_path);
    if (!request->AddEntry(filename, entry_inode, inode_stat.st_mode,
                           next_offset)) {
      // Response buffer full.
      break;
    }

    inode_stat = MakeStat(entry_inode, inode_stat);
    AddCachedInodeStat(inode_stat);
  }

  request->ReplyDone();
}

void SmbFilesystem::ReleaseDir(std::unique_ptr<SimpleRequest> request,
                               fuse_ino_t inode,
                               uint64_t file_handle) {
  VLOG(2) << "ReleaseDir inode: " << inode << " file_handle: " << file_handle;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::ReleaseDirInternal, base::Unretained(this),
                     std::move(request), inode, file_handle));
}

void SmbFilesystem::ReleaseDirInternal(std::unique_ptr<SimpleRequest> request,
                                       fuse_ino_t inode,
                                       uint64_t file_handle) {
  VLOG(2) << "ReleaseDirInternal inode: " << inode
          << " file_handle: " << file_handle;
  if (request->IsInterrupted()) {
    return;
  }

  SMBCFILE* dir = LookupOpenFile(file_handle);
  if (!dir) {
    VLOG(1) << "Bad file handle";
    request->ReplyError(EBADF);
    return;
  }

  int error = samba_impl_->CloseDirectory(dir);
  if (error) {
    VLOG(1) << "CloseDirectory failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  RemoveOpenFile(file_handle);
  request->ReplyOk();
}

void SmbFilesystem::MkDir(std::unique_ptr<EntryRequest> request,
                          fuse_ino_t parent_inode,
                          const std::string& name,
                          mode_t mode) {
  VLOG(2) << "MkDir parent_inode: " << parent_inode << " name: " << name
          << " mode: " << mode;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::MkDirInternal, base::Unretained(this),
                     std::move(request), parent_inode, name, mode));
}

void SmbFilesystem::MkDirInternal(std::unique_ptr<EntryRequest> request,
                                  fuse_ino_t parent_inode,
                                  const std::string& name,
                                  mode_t mode) {
  VLOG(2) << "MkDirInternal parent_inode: " << parent_inode << " name: " << name
          << " mode: " << mode;
  if (request->IsInterrupted()) {
    return;
  }

  const base::FilePath parent_path = inode_map_.GetPath(parent_inode);
  CHECK(!parent_path.empty())
      << "Lookup on invalid parent inode: " << parent_inode;
  const base::FilePath file_path = parent_path.Append(name);
  const std::string share_file_path = MakeShareFilePath(file_path);
  VLOG(2) << "MkDirInternal parent_inode: " << parent_inode << " name: " << name
          << " mode: " << mode << " -> path: " << share_file_path;

  int error = samba_impl_->CreateDirectory(share_file_path, mode);
  if (error) {
    VLOG(1) << "CreateDirectory path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  ino_t inode = inode_map_.IncInodeRef(file_path);
  struct stat entry_stat = MakeStat(inode, {0});
  entry_stat.st_mode = S_IFDIR | mode;
  fuse_entry_param entry = {0};
  entry.ino = inode;
  entry.generation = 1;
  entry.attr = entry_stat;
  // Force readers to see coherent user / group permission bits by not caching
  // stat structure.
  entry.attr_timeout = 0;
  entry.entry_timeout = kAttrTimeoutSeconds;
  request->ReplyEntry(entry);
}

void SmbFilesystem::RmDir(std::unique_ptr<SimpleRequest> request,
                          fuse_ino_t parent_inode,
                          const std::string& name) {
  VLOG(2) << "RmDir parent_inode: " << parent_inode << " name: " << name;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::RmDirinternal, base::Unretained(this),
                     std::move(request), parent_inode, name));
}

void SmbFilesystem::RmDirinternal(std::unique_ptr<SimpleRequest> request,
                                  fuse_ino_t parent_inode,
                                  const std::string& name) {
  VLOG(2) << "RmDirInternal parent_inode: " << parent_inode
          << " name: " << name;
  if (request->IsInterrupted()) {
    return;
  }

  const base::FilePath parent_path = inode_map_.GetPath(parent_inode);
  CHECK(!parent_path.empty())
      << "Lookup on invalid parent inode: " << parent_inode;
  const base::FilePath file_path = parent_path.Append(name);
  const std::string share_file_path = MakeShareFilePath(file_path);
  VLOG(2) << "RmDirInternal parent_inode: " << parent_inode << " name: " << name
          << " -> path: " << share_file_path;

  int error = samba_impl_->RemoveDirectory(share_file_path);
  if (error) {
    VLOG(1) << "RemoveDirectory path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    request->ReplyError(error);
    return;
  }

  request->ReplyOk();
}

void SmbFilesystem::DeleteRecursively(
    const base::FilePath& path,
    RecursiveDeleteOperation::CompletionCallback callback) {
  VLOG(2) << "DeleteRecursively path: " << path;
  samba_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&SmbFilesystem::DeleteRecursivelyInternal,
                     base::Unretained(this), path, std::move(callback)));
}

void SmbFilesystem::DeleteRecursivelyInternal(
    const base::FilePath& path,
    RecursiveDeleteOperation::CompletionCallback callback) {
  VLOG(2) << "DeleteRecursivelyInternal path: " << path;

  if (recursive_delete_operation_) {
    VLOG(1)
        << "Can't start a recursive delete operation whilst one is in progress";
    main_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(std::move(callback),
                       mojom::DeleteRecursivelyError::kOperationInProgress));
    return;
  }

  recursive_delete_operation_.reset(new RecursiveDeleteOperation(
      samba_impl_.get(), MakeShareFilePath(base::FilePath("/")), path,
      base::BindOnce(&SmbFilesystem::OnDeleteRecursivelyDone,
                     base::Unretained(this), std::move(callback))));
  recursive_delete_operation_->Start();
}

void SmbFilesystem::OnDeleteRecursivelyDone(
    RecursiveDeleteOperation::CompletionCallback callback,
    mojom::DeleteRecursivelyError error) {
  CHECK(recursive_delete_operation_);
  recursive_delete_operation_.reset();
  main_task_runner_->PostTask(FROM_HERE,
                              base::BindOnce(std::move(callback), error));
}

std::ostream& operator<<(std::ostream& out, SmbFilesystem::ConnectError error) {
  switch (error) {
    case SmbFilesystem::ConnectError::kOk:
      return out << "kOk";
    case SmbFilesystem::ConnectError::kNotFound:
      return out << "kNotFound";
    case SmbFilesystem::ConnectError::kAccessDenied:
      return out << "kAccessDenied";
    case SmbFilesystem::ConnectError::kSmb1Unsupported:
      return out << "kSmb1Unsupported";
    case SmbFilesystem::ConnectError::kUnknownError:
      return out << "kUnknownError";
    default:
      NOTREACHED();
      return out << "INVALID_ERROR";
  }
}

void SmbFilesystem::AddCachedInodeStat(const struct stat& inode_stat) {
  DCHECK(inode_stat.st_ino);

  StatCacheItem item;

  item.inode_stat = inode_stat;
  item.expires_at = base::Time::Now() + base::Seconds(kStatCacheTimeoutSeconds);

  stat_cache_.Put(inode_stat.st_ino, item);
}

void SmbFilesystem::EraseCachedInodeStat(ino_t inode) {
  auto iter = stat_cache_.Peek(inode);
  if (iter != stat_cache_.end()) {
    stat_cache_.Erase(iter);
  }
}

bool SmbFilesystem::GetCachedInodeStat(ino_t inode, struct stat* out_stat) {
  DCHECK(out_stat);
  auto iter = stat_cache_.Get(inode);
  if (iter == stat_cache_.end()) {
    return false;
  }

  StatCacheItem item = iter->second;
  if (item.expires_at < base::Time::Now()) {
    stat_cache_.Erase(iter);
    return false;
  }

  *out_stat = item.inode_stat;
  return true;
}

}  // namespace smbfs
