// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/proxy_file_system.h"

#include <errno.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>
#include <base/task/task_runner.h>

#include "arc/vm/mojo_proxy/fuse_mount.h"

namespace arc {
namespace {

constexpr char kFileSystemName[] = "arcvm-serverproxy";

// Returns ProxyFileSystem assigned to the FUSE's private_data.
ProxyFileSystem* GetFileSystem(fuse_req_t req) {
  return static_cast<ProxyFileSystem*>(fuse_req_userdata(req));
}

void Lookup(fuse_req_t req, fuse_ino_t parent, const char* name) {
  GetFileSystem(req)->Lookup(req, parent, name);
}

void GetAttr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  GetFileSystem(req)->GetAttr(req, ino, fi);
}

void SetAttr(fuse_req_t req,
             fuse_ino_t ino,
             struct stat* attr,
             int to_set,
             struct fuse_file_info* fi) {
  GetFileSystem(req)->SetAttr(req, ino, attr, to_set, fi);
}

void Open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  GetFileSystem(req)->Open(req, ino, fi);
}

void Read(fuse_req_t req,
          fuse_ino_t ino,
          size_t size,
          off_t off,
          struct fuse_file_info* fi) {
  GetFileSystem(req)->Read(req, ino, size, off, fi);
}

void Write(fuse_req_t req,
           fuse_ino_t ino,
           const char* buf,
           size_t size,
           off_t off,
           struct fuse_file_info* fi) {
  GetFileSystem(req)->Write(req, ino, buf, size, off, fi);
}

void Release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi) {
  GetFileSystem(req)->Release(req, ino, fi);
}

void ReadDir(fuse_req_t req,
             fuse_ino_t ino,
             size_t size,
             off_t off,
             struct fuse_file_info* fi) {
  GetFileSystem(req)->ReadDir(req, ino, size, off, fi);
}

}  // namespace

ProxyFileSystem::ProxyFileSystem(
    Delegate* delegate,
    scoped_refptr<base::TaskRunner> delegate_task_runner,
    const base::FilePath& mount_path)
    : delegate_(delegate),
      delegate_task_runner_(delegate_task_runner),
      mount_path_(mount_path) {}

ProxyFileSystem::~ProxyFileSystem() {
  if (init_task_runner_) {
    base::WaitableEvent stopped(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    init_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](ProxyFileSystem* proxy_file_system, base::WaitableEvent* done) {
              proxy_file_system->fuse_mount_ = nullptr;
              done->Signal();
            },
            base::Unretained(this), &stopped));
    stopped.Wait();
  }
}

bool ProxyFileSystem::Init() {
  DCHECK(!init_task_runner_) << "Init can only be called once.";
  init_task_runner_ = base::SingleThreadTaskRunner::GetCurrentDefault();

  const std::string path_str = mount_path_.value();
  const char* fuse_argv[] = {
      "",  // Dummy argv[0].
  };

  constexpr struct fuse_lowlevel_ops operations = {
      .lookup = arc::Lookup,
      .getattr = arc::GetAttr,
      .setattr = arc::SetAttr,
      .open = arc::Open,
      .read = arc::Read,
      .write = arc::Write,
      .release = arc::Release,
      .readdir = arc::ReadDir,
  };
  fuse_mount_ = std::make_unique<FuseMount>(mount_path_, kFileSystemName);
  if (!fuse_mount_->Init(std::size(fuse_argv), const_cast<char**>(fuse_argv),
                         operations, this)) {
    return false;
  }
  // TODO(hidehiko): Drop CAPS_SYS_ADMIN with minijail setup.
  return true;
}

void ProxyFileSystem::Lookup(fuse_req_t req,
                             fuse_ino_t parent,
                             const char* name) {
  // The parent must be the root directory.
  if (parent != 1) {
    fuse_reply_err(req, ENOENT);
    return;
  }

  // Parse the name as inode;
  uint64_t inode = 0;
  if (!base::StringToUint64(name, &inode)) {
    fuse_reply_err(req, ENOENT);
    return;
  }
  struct fuse_entry_param entry = {};
  entry.ino = static_cast<fuse_ino_t>(inode);
  entry.attr.st_mode = S_IFREG;
  entry.attr.st_nlink = 1;
  fuse_reply_entry(req, &entry);
}

void ProxyFileSystem::GetAttr(fuse_req_t req,
                              fuse_ino_t ino,
                              struct fuse_file_info* fi) {
  if (ino == 1) {  // The root directory.
    struct stat stat = {};
    stat.st_ino = ino, stat.st_mode = S_IFDIR, stat.st_nlink = 2,
    fuse_reply_attr(req, &stat, 0);
    return;
  }

  auto state = GetState(ino);
  if (!state.has_value()) {
    LOG(ERROR) << "Inode not found: " << ino;
    fuse_reply_err(req, ENOENT);
    return;
  }

  struct stat stat = {};
  stat.st_ino = ino;
  stat.st_mode = S_IFREG;
  stat.st_nlink = 1;
  if (!state->is_open) {
    // If the file is not opened yet, this is called from kernel to open the
    // file, which is initiated by the open(2) called in RegisterHandle()
    // on |delegate_task_runner_|.
    // Thus, we cannot make a blocking call to retrieve the size of the file,
    // because it causes deadlock. Instead, we just fill '0', and return
    // immediately.
    stat.st_size = 0;
    fuse_reply_attr(req, &stat, 0);
    return;
  }
  delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ProxyFileSystem::GetAttrInternal, base::Unretained(this),
                     req, state->handle, stat));
}

void ProxyFileSystem::GetAttrInternal(fuse_req_t req,
                                      int64_t handle,
                                      struct stat stat) {
  delegate_->Fstat(handle, base::BindOnce(
                               [](fuse_req_t req, struct stat stat,
                                  int error_code, int64_t size) {
                                 if (error_code == 0) {
                                   stat.st_size = size;
                                   fuse_reply_attr(req, &stat, 0);
                                 } else {
                                   fuse_reply_err(req, error_code);
                                 }
                               },
                               req, stat));
}

void ProxyFileSystem::SetAttr(fuse_req_t req,
                              fuse_ino_t ino,
                              struct stat* attr,
                              int to_set,
                              struct fuse_file_info* fi) {
  auto state = GetState(ino);
  if (!state.has_value()) {
    LOG(ERROR) << "Inode not found: " << ino;
    fuse_reply_err(req, ENOENT);
    return;
  }
  // FUSE_SET_ATTR_SIZE is the only supported flag.
  if (to_set != FUSE_SET_ATTR_SIZE) {
    LOG(ERROR) << "Unsupported to_set flags: " << to_set;
    fuse_reply_err(req, EINVAL);
    return;
  }
  struct stat new_attr = {};
  new_attr.st_ino = ino;
  new_attr.st_mode = S_IFREG;
  new_attr.st_nlink = 1;
  new_attr.st_size = attr->st_size;

  delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ProxyFileSystem::SetAttrInternal, base::Unretained(this),
                     req, state->handle, new_attr));
}

void ProxyFileSystem::SetAttrInternal(fuse_req_t req,
                                      int64_t handle,
                                      struct stat attr) {
  delegate_->Ftruncate(
      handle, attr.st_size,
      base::BindOnce(
          [](fuse_req_t req, struct stat attr, int error_code) {
            if (error_code == 0) {
              fuse_reply_attr(req, &attr, 0);
            } else {
              fuse_reply_err(req, error_code);
            }
          },
          req, attr));
}

void ProxyFileSystem::Open(fuse_req_t req,
                           fuse_ino_t ino,
                           struct fuse_file_info* fi) {
  {
    base::AutoLock lock(inode_lock_);
    auto iter = inode_to_state_.find(ino);
    if (iter == inode_to_state_.end()) {
      LOG(ERROR) << "Inode not found: " << ino;
      fuse_reply_err(req, ENOENT);
      return;
    }
    iter->second.is_open = true;

    fi->direct_io = 1;
    fi->fh = iter->second.handle;
  }
  fuse_reply_open(req, fi);
}

void ProxyFileSystem::Read(fuse_req_t req,
                           fuse_ino_t ino,
                           size_t size,
                           off_t off,
                           struct fuse_file_info* fi) {
  delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ProxyFileSystem::ReadInternal, base::Unretained(this),
                     req, fi->fh, size, off));
}

void ProxyFileSystem::ReadInternal(fuse_req_t req,
                                   int64_t handle,
                                   size_t size,
                                   off_t off) {
  delegate_->Pread(
      handle, size, off,
      base::BindOnce(
          [](fuse_req_t req, int error_code, const std::string& blob) {
            if (error_code == 0) {
              fuse_reply_buf(req, blob.data(), blob.size());
            } else {
              fuse_reply_err(req, error_code);
            }
          },
          req));
}

void ProxyFileSystem::Write(fuse_req_t req,
                            fuse_ino_t ino,
                            const char* buf,
                            size_t size,
                            off_t off,
                            struct fuse_file_info* fi) {
  delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ProxyFileSystem::WriteInternal, base::Unretained(this),
                     req, fi->fh, std::string(buf, size), off));
}

void ProxyFileSystem::WriteInternal(fuse_req_t req,
                                    int64_t handle,
                                    std::string blob,
                                    off_t off) {
  delegate_->Pwrite(
      handle, std::move(blob), off,
      base::BindOnce(
          [](fuse_req_t req, int error_code, int64_t bytes_written) {
            if (error_code == 0) {
              fuse_reply_write(req, bytes_written);
            } else {
              fuse_reply_err(req, error_code);
            }
          },
          req));
}

void ProxyFileSystem::Release(fuse_req_t req,
                              fuse_ino_t ino,
                              struct fuse_file_info* fi) {
  {
    base::AutoLock lock(inode_lock_);
    auto it = inode_to_state_.find(ino);
    if (it == inode_to_state_.end()) {
      LOG(ERROR) << "Inode not found: " << ino;
      fuse_reply_err(req, ENOENT);
      return;
    }
    inode_to_state_.erase(it);
  }

  // |this| outlives |delegate_task_runner_|, so passing raw |this| pointer here
  // is safe.
  delegate_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce([](ProxyFileSystem* self,
                        int64_t handle) { self->delegate_->Close(handle); },
                     this, fi->fh));
  fuse_reply_err(req, 0);
}

void ProxyFileSystem::ReadDir(fuse_req_t req,
                              fuse_ino_t ino,
                              size_t size,
                              off_t off,
                              struct fuse_file_info* fi) {
  // It must be the root directory.
  if (ino != 1) {
    fuse_reply_err(req, ENOTDIR);
    return;
  }

  // Just returns as if it is empty directory.
  const char* kEntryNames[] = {
      ".",
      "..",
  };
  std::vector<char> buf;
  for (const char* entry_name : kEntryNames) {
    const size_t offset = buf.size();
    // Make space for the entry.
    const size_t entry_size =
        fuse_add_direntry(req, nullptr, 0, entry_name, nullptr, 0);
    buf.resize(buf.size() + entry_size);
    // Add the entry to the buffer.
    struct stat st = {
        .st_ino = ino,
    };
    fuse_add_direntry(req, buf.data() + offset, entry_size, entry_name, &st,
                      buf.size());
  }
  // Send reply.
  fuse_reply_buf(req, buf.data() + off,
                 std::min(buf.size() - static_cast<size_t>(off), size));
}

base::ScopedFD ProxyFileSystem::RegisterHandle(int64_t handle, int32_t flags) {
  fuse_ino_t inode = 0;
  {
    base::AutoLock lock(inode_lock_);
    State state = {
        .handle = handle,
        .is_open = false,
    };
    inode = next_inode_++;
    if (!inode_to_state_.emplace(inode, state).second) {
      LOG(ERROR) << "Failed to register inode: " << inode;
      return {};
    }
  }

  const int32_t new_flags = O_CLOEXEC | (flags & O_ACCMODE);
  return base::ScopedFD(HANDLE_EINTR(
      open(mount_path_.Append(base::NumberToString(inode)).value().c_str(),
           new_flags)));
}

std::optional<ProxyFileSystem::State> ProxyFileSystem::GetState(
    fuse_ino_t inode) {
  base::AutoLock lock_(inode_lock_);
  auto iter = inode_to_state_.find(inode);
  if (iter == inode_to_state_.end())
    return std::nullopt;
  return iter->second;
}

}  // namespace arc
