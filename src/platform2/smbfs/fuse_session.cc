// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/fuse_session.h"

#include <errno.h>
#include <fuse_opt.h>
#include <unistd.h>

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>
#include <base/strings/stringprintf.h>

#include "smbfs/filesystem.h"
#include "smbfs/request.h"
#include "smbfs/util.h"

namespace smbfs {

class FuseSession::Impl {
 public:
  Impl(FuseSession* session, std::unique_ptr<Filesystem> fs)
      : session_(session), fs_(std::move(fs)) {
    DCHECK(fs_);
  }
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  ~Impl() = default;

  // FUSE low-level operations. See fuse_lowlevel_ops in fuse_lowlevel.h for
  // details.
  static void FuseDestroy(void* userdata) {
    static_cast<Impl*>(userdata)->Destroy();
  }

  static void FuseStatFs(fuse_req_t request, fuse_ino_t inode) {
    static_cast<Impl*>(fuse_req_userdata(request))->StatFs(request, inode);
  }

  static void FuseLookup(fuse_req_t request,
                         fuse_ino_t parent_inode,
                         const char* name) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Lookup(request, parent_inode, name);
  }

  static void FuseForget(fuse_req_t request,
                         fuse_ino_t inode,
                         unsigned long count) {  // NOLINT(runtime/int)
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Forget(request, inode, count);
  }

  static void FuseGetAttr(fuse_req_t request,
                          fuse_ino_t inode,
                          fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->GetAttr(request, inode, info);
  }

  static void FuseSetAttr(fuse_req_t request,
                          fuse_ino_t inode,
                          struct stat* attr,
                          int to_set,
                          fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->SetAttr(request, inode, attr, to_set, info);
  }

  static void FuseOpen(fuse_req_t request,
                       fuse_ino_t inode,
                       fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))->Open(request, inode, info);
  }

  static void FuseCreate(fuse_req_t request,
                         fuse_ino_t parent_inode,
                         const char* name,
                         mode_t mode,
                         fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Create(request, parent_inode, name, mode, info);
  }

  static void FuseRead(fuse_req_t request,
                       fuse_ino_t inode,
                       size_t size,
                       off_t off,
                       fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Read(request, inode, size, off, info);
  }

  static void FuseWrite(fuse_req_t request,
                        fuse_ino_t inode,
                        const char* buf,
                        size_t size,
                        off_t off,
                        fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Write(request, inode, buf, size, off, info);
  }

  static void FuseRelease(fuse_req_t request,
                          fuse_ino_t inode,
                          fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Release(request, inode, info);
  }

  static void FuseRename(fuse_req_t request,
                         fuse_ino_t old_parent,
                         const char* old_name,
                         fuse_ino_t new_parent,
                         const char* new_name) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Rename(request, old_parent, old_name, new_parent, new_name);
  }

  static void FuseUnlink(fuse_req_t request,
                         fuse_ino_t parent_inode,
                         const char* name) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->Unlink(request, parent_inode, name);
  }

  static void FuseOpenDir(fuse_req_t request,
                          fuse_ino_t inode,
                          fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->OpenDir(request, inode, info);
  }

  static void FuseReadDir(fuse_req_t request,
                          fuse_ino_t inode,
                          size_t size,
                          off_t off,
                          fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->ReadDir(request, inode, size, off, info);
  }

  static void FuseReleaseDir(fuse_req_t request,
                             fuse_ino_t inode,
                             fuse_file_info* info) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->ReleaseDir(request, inode, info);
  }

  static void FuseMkDir(fuse_req_t request,
                        fuse_ino_t parent_inode,
                        const char* name,
                        mode_t mode) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->MkDir(request, parent_inode, name, mode);
  }

  static void FuseRmDir(fuse_req_t request,
                        fuse_ino_t parent_inode,
                        const char* name) {
    static_cast<Impl*>(fuse_req_userdata(request))
        ->RmDir(request, parent_inode, name);
  }

 private:
  void Destroy() {
    VLOG(1) << "FuseSession::Destroy";
    session_->RequestStop();
  }

  void StatFs(fuse_req_t request, fuse_ino_t inode) {
    VLOG(1) << "FuseSession::StatFs inode: " << inode;
    fs_->StatFs(std::make_unique<StatFsRequest>(request), inode);
  }

  void Lookup(fuse_req_t request, fuse_ino_t parent_inode, const char* name) {
    VLOG(1) << "FuseSession::Lookup parent: " << parent_inode
            << " name:" << name;
    fs_->Lookup(std::make_unique<EntryRequest>(request), parent_inode, name);
  }

  void Forget(fuse_req_t request,
              fuse_ino_t inode,
              unsigned long count) {  // NOLINT(runtime/int)
    VLOG(1) << "FuseSession::Forget inode: " << inode << " count:" << count;
    fs_->Forget(inode, count);
    fuse_reply_none(request);
  }

  void GetAttr(fuse_req_t request,
               fuse_ino_t inode,
               fuse_file_info* unused_info) {
    VLOG(1) << "FuseSession::GetAttr: " << inode;
    fs_->GetAttr(std::make_unique<AttrRequest>(request), inode);
  }

  void SetAttr(fuse_req_t request,
               fuse_ino_t inode,
               struct stat* attr,
               int to_set,
               fuse_file_info* info) {
    VLOG(1) << "FuseSession::SetAttr: " << inode
            << " to_set: " << ToSetFlagsToString(to_set)
            << " handle: " << (info ? info->fh : 0);
    fs_->SetAttr(std::make_unique<AttrRequest>(request), inode,
                 info ? info->fh : std::optional<uint64_t>(), *attr, to_set);
  }

  void Open(fuse_req_t request, fuse_ino_t inode, fuse_file_info* info) {
    VLOG(1) << "FuseSession::Open inode: " << inode
            << " flags: " << OpenFlagsToString(info->flags);
    fs_->Open(std::make_unique<OpenRequest>(request), inode, info->flags);
  }

  void Create(fuse_req_t request,
              fuse_ino_t parent_inode,
              const char* name,
              mode_t mode,
              fuse_file_info* info) {
    VLOG(1) << "FuseSession::Create parent: " << parent_inode
            << " name: " << name << " mode: " << base::StringPrintf("0%o", mode)
            << " flags: " << OpenFlagsToString(info->flags);
    fs_->Create(std::make_unique<CreateRequest>(request), parent_inode, name,
                mode, info->flags);
  }

  void Read(fuse_req_t request,
            fuse_ino_t inode,
            size_t size,
            off_t off,
            fuse_file_info* info) {
    VLOG(1) << "FuseSession::Read inode: " << inode << " handle:" << info->fh
            << " offset: " << off << " size: " << size;
    fs_->Read(std::make_unique<BufRequest>(request), inode, info->fh, size,
              off);
  }

  void Write(fuse_req_t request,
             fuse_ino_t inode,
             const char* buf,
             size_t size,
             off_t off,
             fuse_file_info* info) {
    VLOG(1) << "FuseSession::Write inode: " << inode << " handle:" << info->fh
            << " offset: " << off << " size: " << size;
    fs_->Write(std::make_unique<WriteRequest>(request), inode, info->fh, buf,
               size, off);
  }

  void Release(fuse_req_t request, fuse_ino_t inode, fuse_file_info* info) {
    VLOG(1) << "FuseSession::Release inode: " << inode
            << " handle:" << info->fh;
    fs_->Release(std::make_unique<SimpleRequest>(request), inode, info->fh);
  }

  void Rename(fuse_req_t request,
              fuse_ino_t old_parent,
              const char* old_name,
              fuse_ino_t new_parent,
              const char* new_name) {
    VLOG(1) << "FuseSession::Rename old_parent: " << old_parent
            << " old_name: " << old_name << " new_parent: " << new_parent
            << " new_name: " << new_name;
    fs_->Rename(std::make_unique<SimpleRequest>(request), old_parent, old_name,
                new_parent, new_name);
  }

  void Unlink(fuse_req_t request, fuse_ino_t parent_inode, const char* name) {
    VLOG(1) << "FuseSession::Unlink parent_inode: " << parent_inode
            << " name: " << name;
    fs_->Unlink(std::make_unique<SimpleRequest>(request), parent_inode, name);
  }

  void OpenDir(fuse_req_t request, fuse_ino_t inode, fuse_file_info* info) {
    VLOG(1) << "FuseSession::OpenDir inode: " << inode
            << " flags: " << OpenFlagsToString(info->flags);
    fs_->OpenDir(std::make_unique<OpenRequest>(request), inode, info->flags);
  }

  void ReadDir(fuse_req_t request,
               fuse_ino_t inode,
               size_t size,
               off_t off,
               fuse_file_info* info) {
    VLOG(1) << "FuseSession::ReadDir inode: " << inode << " handle:" << info->fh
            << " offset: " << off;
    fs_->ReadDir(std::make_unique<DirentryRequest>(request, size), inode,
                 info->fh, off);
  }

  void ReleaseDir(fuse_req_t request, fuse_ino_t inode, fuse_file_info* info) {
    VLOG(1) << "FuseSession::ReleaseDir inode: " << inode
            << " handle:" << info->fh;
    fs_->ReleaseDir(std::make_unique<SimpleRequest>(request), inode, info->fh);
  }

  void MkDir(fuse_req_t request,
             fuse_ino_t parent_inode,
             const char* name,
             mode_t mode) {
    VLOG(1) << "FuseSession::MkDir parent_inode: " << parent_inode
            << " name:" << name << " mode: " << base::StringPrintf("0%o", mode);
    fs_->MkDir(std::make_unique<EntryRequest>(request), parent_inode, name,
               mode);
  }

  void RmDir(fuse_req_t request, fuse_ino_t parent_inode, const char* name) {
    VLOG(1) << "FuseSession::RmDir parent_inode: " << parent_inode
            << " name:" << name;
    fs_->RmDir(std::make_unique<SimpleRequest>(request), parent_inode, name);
  }

  FuseSession* session_;
  std::unique_ptr<Filesystem> fs_;
};

FuseSession::FuseSession(std::unique_ptr<Filesystem> fs, fuse_chan* chan)
    : impl_(std::make_unique<Impl>(this, std::move(fs))), chan_(chan) {
  DCHECK(chan_);
}

FuseSession::~FuseSession() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  // Ensure |stop_callback_| isn't called as a result of destruction.
  stop_callback_.Reset();

  if (session_) {
    // Disconnect the channel from the fuse_session before destroying them both.
    // fuse_session_destroy() also destroys the attached channel (not
    // documented). Disconnecting the two simplifies logic, and ensures
    // FuseSession maintains ownership of the fuse_chan.
    fuse_session_remove_chan(chan_);
    fuse_session_destroy(session_);
  }
  fuse_chan_destroy(chan_);
}

bool FuseSession::Start(base::OnceClosure stop_callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  CHECK_EQ(session_, nullptr);

  fuse_lowlevel_ops ops = {0};
  ops.destroy = &Impl::FuseDestroy;
  ops.statfs = &Impl::FuseStatFs;
  ops.lookup = &Impl::FuseLookup;
  ops.forget = &Impl::FuseForget;
  ops.getattr = &Impl::FuseGetAttr;
  ops.setattr = &Impl::FuseSetAttr;
  ops.open = &Impl::FuseOpen;
  ops.create = &Impl::FuseCreate;
  ops.read = &Impl::FuseRead;
  ops.write = &Impl::FuseWrite;
  ops.release = &Impl::FuseRelease;
  ops.rename = &Impl::FuseRename;
  ops.unlink = &Impl::FuseUnlink;
  ops.opendir = &Impl::FuseOpenDir;
  ops.readdir = &Impl::FuseReadDir;
  ops.releasedir = &Impl::FuseReleaseDir;
  ops.mkdir = &Impl::FuseMkDir;
  ops.rmdir = &Impl::FuseRmDir;

  struct fuse_args args = {0};
  // The first argument needs to be the program name, which is ignored by the
  // options parser.
  CHECK_EQ(fuse_opt_add_arg(&args, "smbfs"), 0);
  CHECK_EQ(fuse_opt_add_arg(&args, "-obig_writes"), 0);

  session_ = fuse_lowlevel_new(&args, &ops, sizeof(ops), impl_.get());
  if (!session_) {
    LOG(ERROR) << "Unable to create new FUSE session";
    return false;
  }
  fuse_session_add_chan(session_, chan_);
  read_buffer_.resize(fuse_chan_bufsize(chan_));

  CHECK(base::SetNonBlocking(fuse_chan_fd(chan_)));
  read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fuse_chan_fd(chan_), base::BindRepeating(&FuseSession::OnChannelReadable,
                                               base::Unretained(this)));
  stop_callback_ = std::move(stop_callback);

  return true;
}

void FuseSession::OnChannelReadable() {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  VLOG(2) << "FuseSession::OnChannelReadable";
  fuse_buf buf = {0};
  buf.mem = read_buffer_.data();
  buf.size = read_buffer_.size();
  fuse_chan* temp_chan = chan_;
  int read_size = fuse_session_receive_buf(session_, &buf, &temp_chan);
  if (read_size == 0) {
    // A read of 0 indicates the filesystem has been unmounted and the kernel
    // driver has closed the fuse session.
    LOG(INFO) << "FUSE kernel channel closed, shutting down";
    RequestStop();
    return;
  } else if (read_size == -EINTR) {
    // Since FD watching is level-triggered, this function will get called again
    // very soon to try again.
    return;
  } else if (read_size < 0) {
    LOG(ERROR) << "FUSE channel read failed with error: "
               << base::safe_strerror(-read_size) << " [" << -read_size
               << "], shutting down";
    RequestStop();
    return;
  }

  fuse_session_process_buf(session_, &buf, chan_);
}

void FuseSession::RequestStop() {
  read_watcher_.reset();

  if (stop_callback_) {
    std::move(stop_callback_).Run();
  }
}

}  // namespace smbfs
