// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FUSEBOX_FUSE_FRONTEND_H_
#define FUSEBOX_FUSE_FRONTEND_H_

#include <fuse_lowlevel.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>

namespace fusebox {

/**
 * FuseBox needs user-space (client) code to 1) create and start a FUSE
 * user-space session, and 2) read and process Kernel FUSE requests for
 * the session.
 *
 * A FuseMount object is provided to the FuseFrontend class, containing
 * the active |mountpoint| name, and Kernel FUSE channel |chan|, needed
 * to create the session with fuse_lowlevel_new(3).
 *
 * FuseFrontend::CreateFuseSession() creates the FUSE session, and then
 * StartFuseSession() can be used to start and run the session.
 *
 * The session is connected to Kernel FUSE over the provided |chan| and
 * reads Kernel FUSE requests from the |chan| file descriptor and sends
 * them to libFUSE, where they are processed into FUSE operations. This
 * is handled by FuseFrontend::OnFuseChannelReadable().
 *
 * Note an EINTR error while reading the channel can be ignored: Kernel
 * FUSE will notice and re-send requests in this case (request delivery
 * is reliable in FUSE).
 *
 * Kernel FUSE may close the session: due to a umount(8) which unmounts
 * the mountpoint or by sending an error (negative read on |chan|). The
 * class owner is told with the stop callback, and should tear-down the
 * session. The class owner can also call StopFuseSession() to stop the
 * session and invoke the stop callback.
 *
 * Session tear-down and clean-up: class owner deletes the FuseFrontend
 * which exits the session using fuse_session_exit(3).
 */

struct FuseMount {
  FuseMount(char** m, fuse_chan* c) : mountpoint(m), chan(c) {}
  char** mountpoint;
  fuse_chan* chan;
  std::string opts;
  bool debug = false;
};

class FuseFrontend {
 public:
  explicit FuseFrontend(FuseMount* fuse)
      : fuse_(fuse), weak_ptr_factory_(this) {}

  FuseFrontend(const FuseFrontend&) = delete;
  FuseFrontend& operator=(const FuseFrontend&) = delete;

  ~FuseFrontend() {
    read_watcher_.reset();
    stop_callback_.Reset();
    if (session_)
      fuse_session_exit(session_);
  }

  bool CreateFuseSession(void* userdata, fuse_lowlevel_ops fops) {
    struct fuse_args args = {0};

    CHECK_EQ(0, fuse_opt_add_arg(&args, "fusebox"));
    if (fuse_->debug)
      CHECK_EQ(0, fuse_opt_add_arg(&args, "-d"));
    if (!fuse_->opts.empty())
      CHECK_EQ(0, fuse_opt_add_arg(&args, ("-o" + fuse_->opts).c_str()));

    CHECK(!session_);
    session_ = fuse_lowlevel_new(&args, &fops, sizeof(fops), userdata);
    if (!session_) {
      PLOG(ERROR) << "fuse_lowlevel_new() failed";
      return false;
    }

    CHECK(fuse_->chan);
    fuse_session_add_chan(session_, fuse_->chan);
    return true;
  }

  void StartFuseSession(base::OnceClosure stop_callback) {
    stop_callback_ = std::move(stop_callback);
    fuse_chan* chan = fuse_->chan;

    CHECK(stop_callback_);
    CHECK(session_);
    CHECK(chan);

    CHECK(base::SetNonBlocking(fuse_chan_fd(chan)));
    read_buffer_.resize(fuse_chan_bufsize(chan));

    auto fuse_chan_readable = base::BindRepeating(
        &FuseFrontend::OnFuseChannelReadable, weak_ptr_factory_.GetWeakPtr());
    read_watcher_ = base::FileDescriptorWatcher::WatchReadable(
        fuse_chan_fd(chan), std::move(fuse_chan_readable));
  }

  void StopFuseSession(int error) {
    if (stop_callback_) {
      errno = error;
      std::move(stop_callback_).Run();
    }
  }

 private:
  void OnFuseChannelReadable() {
    fuse_buf buf = {0};
    buf.mem = read_buffer_.data();
    buf.size = read_buffer_.size();

    fuse_chan* chan = fuse_->chan;
    int read_size = fuse_session_receive_buf(session_, &buf, &chan);
    if (read_size == -EINTR)
      return;

    if (read_size == 0) {
      LOG(INFO) << "Kernel FUSE : umount(8) " << *fuse_->mountpoint;
      *fuse_->mountpoint = nullptr;
      StopFuseSession(ENODEV);
      return;
    }

    if (read_size < 0) {
      std::string kernel_error = base::safe_strerror(-read_size);
      LOG(ERROR) << "Kernel FUSE : " << kernel_error;
      StopFuseSession(-read_size);
      return;
    }

    fuse_session_process_buf(session_, &buf, chan);
  }

  // Fuse mount: not owned.
  FuseMount* fuse_ = nullptr;

  // Fuse user-space session.
  fuse_session* session_ = nullptr;

  // Fuse kernel-space channel reader.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> read_watcher_;

  // Fixed-size buffer to receive Kernel Fuse requests.
  std::vector<char> read_buffer_;

  // Called if Kernel Fuse or the class owner stops the session.
  base::OnceClosure stop_callback_;

  base::WeakPtrFactory<FuseFrontend> weak_ptr_factory_;
};

}  // namespace fusebox

#endif  // FUSEBOX_FUSE_FRONTEND_H_
