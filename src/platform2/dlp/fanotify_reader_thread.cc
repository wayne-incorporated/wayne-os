// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/fanotify_reader_thread.h"

#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/posix/eintr_wrapper.h"
#include "base/task/sequenced_task_runner.h"
#include "base/threading/platform_thread.h"
#include "dlp/dlp_metrics.h"

namespace {

// TODO(b/259688785): Update fanofity headers to include the struct.
/* Variable length info record following event metadata */
struct fanotify_event_info_header {
  __u8 info_type;
  __u8 pad;
  __u16 len;
};

// TODO(b/259688785): Update fanofity headers to include the struct.
/*
 * Unique file identifier info record.
 * This structure is used for records of types FAN_EVENT_INFO_TYPE_FID,
 * FAN_EVENT_INFO_TYPE_DFID and FAN_EVENT_INFO_TYPE_DFID_NAME.
 * For FAN_EVENT_INFO_TYPE_DFID_NAME there is additionally a null terminated
 * name immediately after the file handle.
 */
struct fanotify_event_info_fid {
  struct fanotify_event_info_header hdr;
  __kernel_fsid_t fsid;
  /*
   * Following is an opaque struct file_handle that can be passed as
   * an argument to open_by_handle_at(2).
   */
  unsigned char handle[];
};

}  // namespace

namespace dlp {

FanotifyReaderThread::FanotifyReaderThread(
    scoped_refptr<base::SequencedTaskRunner> parent_task_runner,
    Delegate* delegate)
    : parent_task_runner_(std::move(parent_task_runner)), delegate_(delegate) {
  CHECK(delegate_);
  CHECK(parent_task_runner_->RunsTasksInCurrentSequence());
}

FanotifyReaderThread::~FanotifyReaderThread() {
  base::PlatformThread::Join(handle_);
}

void FanotifyReaderThread::StartThread(int fanotify_fd) {
  CHECK(parent_task_runner_->RunsTasksInCurrentSequence());
  fanotify_fd_ = fanotify_fd;

  CHECK(base::PlatformThread::Create(0, this, &handle_));
}

void FanotifyReaderThread::ThreadMain() {
  CHECK(!parent_task_runner_->RunsTasksInCurrentSequence());
  base::PlatformThread::SetName("fanotify_reader");

  RunLoop();

  // TODO(poromov): Gracefully stop the thread and notify.
}

void FanotifyReaderThread::RunLoop() {
  CHECK(!parent_task_runner_->RunsTasksInCurrentSequence());

  CHECK_LE(0, fanotify_fd_);
  CHECK_GT(FD_SETSIZE, fanotify_fd_);

  // Set constant large buffer size per fanotify man page recommendations.
  char buffer[4096];
  while (true) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fanotify_fd_, &rfds);
    // Re-check file descriptor every second.
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // Wait until some fanotify events are available.
    int select_result =
        HANDLE_EINTR(select(fanotify_fd_ + 1, &rfds, nullptr, nullptr, &tv));
    if (select_result < 0) {
      PLOG(WARNING) << "select failed";
      ForwardUMAErrorToParentThread(FanotifyError::kSelectError);
      return;
    } else if (select_result == 0) {
      continue;
    }

    ssize_t bytes_read =
        HANDLE_EINTR(read(fanotify_fd_, buffer, sizeof(buffer)));
    if (bytes_read < 0) {
      PLOG(WARNING) << "read from fanotify fd failed";
      ForwardUMAErrorToParentThread(FanotifyError::kFdError);
      return;
    }

    fanotify_event_metadata* metadata =
        reinterpret_cast<fanotify_event_metadata*>(&buffer[0]);
    for (; FAN_EVENT_OK(metadata, bytes_read);
         metadata = FAN_EVENT_NEXT(metadata, bytes_read)) {
      if (metadata->vers != FANOTIFY_METADATA_VERSION) {
        LOG(ERROR) << "mismatch of fanotify metadata version";
        ForwardUMAErrorToParentThread(FanotifyError::kMetadataMismatchError);
        return;
      }
      if (metadata->mask & FAN_OPEN_PERM) {
        if (metadata->fd < 0) {
          LOG(ERROR) << "invalid file descriptor for OPEN_PERM event";
          ForwardUMAErrorToParentThread(
              FanotifyError::kInvalidFileDescriptorError);
          continue;
        }
        base::ScopedFD fd(metadata->fd);
        struct stat st;
        if (fstat(fd.get(), &st)) {
          PLOG(ERROR) << "fstat failed";
          ForwardUMAErrorToParentThread(FanotifyError::kFstatError);
          continue;
        }

        parent_task_runner_->PostTask(
            FROM_HERE, base::BindOnce(&Delegate::OnFileOpenRequested,
                                      base::Unretained(delegate_), st.st_ino,
                                      metadata->pid, std::move(fd)));
      } else if (metadata->mask & FAN_DELETE_SELF) {
        struct file_handle* file_handle;
        struct fanotify_event_info_fid* fid;
        fid = (struct fanotify_event_info_fid*)(metadata + 1);
        // TODO(b/259688785): Update fanofity headers to include the const.
        if (fid->hdr.info_type != /*FAN_EVENT_INFO_TYPE_FID=*/1) {
          LOG(ERROR) << "expected FID type DELETE_SELF event";
          ForwardUMAErrorToParentThread(
              FanotifyError::kUnexpectedEventInfoTypeError);
          continue;
        }

        file_handle = (struct file_handle*)fid->handle;
        uint32_t* handle = reinterpret_cast<uint32_t*>(file_handle->f_handle);
        if (file_handle->handle_type != /*FILEID_INO32_GEN=*/1) {
          LOG(ERROR) << "unexpected file_handle type: "
                     << file_handle->handle_type;
          ForwardUMAErrorToParentThread(
              FanotifyError::kUnexpectedFileHandleTypeError);
          continue;
        }
        parent_task_runner_->PostTask(
            FROM_HERE, base::BindOnce(&Delegate::OnFileDeleted,
                                      base::Unretained(delegate_), handle[0]));
      } else {
        LOG(WARNING) << "unexpected fanotify event: " << metadata->mask;
        ForwardUMAErrorToParentThread(FanotifyError::kUnknownError);
      }
    }
  }
}

void FanotifyReaderThread::ForwardUMAErrorToParentThread(FanotifyError error) {
  parent_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&Delegate::OnFanotifyError,
                                base::Unretained(delegate_), error));
}

}  // namespace dlp
