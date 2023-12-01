// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/fanotify_watcher.h"

#include <fcntl.h>
#include <memory>
#include <sys/fanotify.h>
#include <utility>

#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/posix/eintr_wrapper.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "dlp/fanotify_reader_thread.h"
#include "dlp/kernel_version_tools.h"

namespace dlp {

FanotifyWatcher::FanotifyWatcher(Delegate* delegate,
                                 int fanotify_perm_fd,
                                 int fanotify_notif_fd)
    : task_runner_(base::SequencedTaskRunner::GetCurrentDefault()),
      fd_events_thread_(task_runner_, this),
      fh_events_thread_(task_runner_, this),
      fanotify_fd_events_fd_(fanotify_perm_fd),
      fanotify_fh_events_fd_(fanotify_notif_fd),
      delegate_(delegate) {
  DCHECK(delegate);

  fd_events_thread_.StartThread(fanotify_fd_events_fd_.get());

  if (GetKernelVersion() >= kMinKernelVersionForFanDeleteEvents) {
    fh_events_thread_.StartThread(fanotify_fh_events_fd_.get());
  }
}

FanotifyWatcher::~FanotifyWatcher() = default;

void FanotifyWatcher::AddFileDeleteWatch(const base::FilePath& path) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  if (GetKernelVersion() >= kMinKernelVersionForFanDeleteEvents) {
    int res = fanotify_mark(fanotify_fh_events_fd_.get(), FAN_MARK_ADD,
                            FAN_DELETE_SELF, AT_FDCWD, path.value().c_str());

    if (res != 0) {
      PLOG(ERROR) << "fanotify_mark for DELETE_SELF (" << path << ") failed";
      OnFanotifyError(FanotifyError::kMarkError);
    } else {
      LOG(INFO) << "Added watch for: " << path;
    }
  }
}

void FanotifyWatcher::SetActive(bool active) {
  active_ = active;
}

bool FanotifyWatcher::IsActive() const {
  return active_;
}

FanotifyWatcher::FanotifyReplyWatchdog::FanotifyReplyWatchdog()
    : watchdog_(
          base::Milliseconds(1000), "DLP daemon", /*enabled=*/true, this) {}
FanotifyWatcher::FanotifyReplyWatchdog::~FanotifyReplyWatchdog() = default;

void FanotifyWatcher::FanotifyReplyWatchdog::Arm() {
  watchdog_.Arm();
}

void FanotifyWatcher::FanotifyReplyWatchdog::Disarm() {
  watchdog_.Disarm();
}

void FanotifyWatcher::FanotifyReplyWatchdog::Alarm() {
  LOG(ERROR) << "DLP thread hang, watchdog triggered, exiting abnormally";
  _exit(2);
}

void FanotifyWatcher::OnFileOpenRequested(ino_t inode,
                                          int pid,
                                          base::ScopedFD fd) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  std::unique_ptr<FanotifyReplyWatchdog> watchdog =
      std::make_unique<FanotifyReplyWatchdog>();
  watchdog->Arm();
  fanotify_request_watchdogs_[++last_watchdog_id_] = std::move(watchdog);
  CHECK(fanotify_fd_events_fd_.is_valid());

  if (!active_) {
    OnRequestProcessed(std::move(fd), last_watchdog_id_, /*allowed=*/true);
    return;
  }

  delegate_->ProcessFileOpenRequest(
      inode, pid,
      base::BindOnce(&FanotifyWatcher::OnRequestProcessed,
                     base::Unretained(this), std::move(fd), last_watchdog_id_));
}

void FanotifyWatcher::OnFileDeleted(ino_t inode) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  delegate_->OnFileDeleted(inode);
}

void FanotifyWatcher::OnFanotifyError(FanotifyError error) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  delegate_->OnFanotifyError(error);
}

void FanotifyWatcher::OnRequestProcessed(base::ScopedFD fd,
                                         int watchdog_id,
                                         bool allowed) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  struct fanotify_response response = {};
  response.fd = fd.get();
  response.response = allowed ? FAN_ALLOW : FAN_DENY;
  HANDLE_EINTR(
      write(fanotify_fd_events_fd_.get(), &response, sizeof(response)));

  fanotify_request_watchdogs_[watchdog_id]->Disarm();
  fanotify_request_watchdogs_.erase(watchdog_id);
}

}  // namespace dlp
