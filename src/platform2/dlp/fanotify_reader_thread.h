// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLP_FANOTIFY_READER_THREAD_H_
#define DLP_FANOTIFY_READER_THREAD_H_

#include "base/files/scoped_file.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/threading/platform_thread.h"
#include "dlp/dlp_metrics.h"

namespace dlp {

// Reads events from fanotify file descriptor and post them to the delegate.
class FanotifyReaderThread : public base::PlatformThread::Delegate {
 public:
  class Delegate {
   public:
    // Request to process the file |inode| open request from process |pid|.
    // |fd| is the file descriptor to the file.
    virtual void OnFileOpenRequested(ino_t inode,
                                     int pid,
                                     base::ScopedFD fd) = 0;

    // Called when a file with |inode| was deleted. The file might already not
    // exist on the filesystem.
    virtual void OnFileDeleted(ino_t inode) = 0;

    // Called when an error occurres.
    virtual void OnFanotifyError(FanotifyError error) = 0;

   protected:
    virtual ~Delegate() = default;
  };

  FanotifyReaderThread(
      scoped_refptr<base::SequencedTaskRunner> parent_task_runner,
      Delegate* delegate);
  ~FanotifyReaderThread() override;

  // Starts the thread to read events from |fanotify_fd|.
  void StartThread(int fanotify_fd);

 private:
  // base::PlatformThread::Delegate overrides:
  void ThreadMain() override;

  void RunLoop();

  void ForwardUMAErrorToParentThread(FanotifyError error);

  // Task runner from which this thread is started and where the delegate is
  // running.
  scoped_refptr<base::SequencedTaskRunner> parent_task_runner_;
  Delegate* const delegate_;
  int fanotify_fd_ = -1;
  base::PlatformThreadHandle handle_;
};

}  // namespace dlp

#endif  // DLP_FANOTIFY_READER_THREAD_H_
