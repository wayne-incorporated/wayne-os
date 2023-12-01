/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_THREAD_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_THREAD_H_

#include <string>
#include <unordered_map>
#include <utility>

#include <base/location.h>
#include <base/threading/thread.h>

#include "cros-camera/common.h"
#include "cros-camera/export.h"
#include "cros-camera/future.h"

namespace cros {

class CROS_CAMERA_EXPORT CameraThread {
 public:
  explicit CameraThread(std::string name) : thread_(name) {}

  CameraThread(const CameraThread&) = delete;
  CameraThread& operator=(const CameraThread&) = delete;

  // Starts the thread. Returns true if the thread was successfully started.
  bool Start() {
    if (!thread_.Start()) {
      LOG(ERROR) << "Failed to start thread";
      return false;
    }
    thread_.WaitUntilThreadStarted();
    return true;
  }

  // Stop the thread. This function is expected to be called explicitly. A fatal
  // error would have occured in the AtExitManager if it were called in
  // the destructor.
  void Stop() { thread_.Stop(); }

  // Returns true if this is the current thread that is running.
  bool IsCurrentThread() const {
    return thread_.GetThreadId() == base::PlatformThread::CurrentId();
  }

  // Posts the given task to be run and wait till it is finished. The reply
  // from callee will be stored in |result|. Return 0 if succeed. Otherwise
  // return -EIO.
  template <typename T>
  int PostTaskSync(const base::Location& from_here,
                   base::OnceCallback<T()> task,
                   T* result) {
    if (!thread_.task_runner()) {
      LOG(ERROR) << "Thread is not started";
      return -EIO;
    }

    auto future = cros::Future<T>::Create(nullptr);
    base::OnceClosure closure =
        base::BindOnce(&CameraThread::ProcessSyncTaskOnThread<T>,
                       base::Unretained(this), std::move(task), future);
    if (!thread_.task_runner()->PostTask(from_here, std::move(closure))) {
      LOG(ERROR) << "Failed to post task";
      return -EIO;
    }

    *result = future->Get();
    return 0;
  }

  // Posts the given task to be run asynchronously. Return 0 if succeed.
  // Otherwise return -EIO.
  template <typename T>
  int PostTaskAsync(const base::Location& from_here,
                    base::OnceCallback<T()> task) {
    if (!thread_.task_runner()) {
      LOG(ERROR) << "Thread is not started";
      return -EIO;
    }
    base::OnceClosure closure =
        base::BindOnce(&CameraThread::ProcessAsyncTaskOnThread<T>,
                       base::Unretained(this), std::move(task));

    if (!thread_.task_runner()->PostTask(from_here, std::move(closure))) {
      LOG(ERROR) << "Failed to post task";
      return -EIO;
    }
    return 0;
  }

  // Posts the given task to be run and wait till it is finished.
  // Return 0 if succeed. Otherwise return -EIO.
  int PostTaskSync(const base::Location& from_here, base::OnceClosure task) {
    if (!thread_.task_runner()) {
      LOG(ERROR) << "Thread is not started";
      return -EIO;
    }

    auto future = cros::Future<void>::Create(nullptr);
    base::OnceClosure closure =
        base::BindOnce(&CameraThread::ProcessClosureSyncTaskOnThread,
                       base::Unretained(this), std::move(task), future);
    if (!thread_.task_runner()->PostTask(from_here, std::move(closure))) {
      LOG(ERROR) << "Failed to post task";
      return -EIO;
    }

    future->Wait();
    return 0;
  }

  scoped_refptr<base::SingleThreadTaskRunner> task_runner() const {
    return thread_.task_runner();
  }

 private:
  template <typename T>
  void ProcessSyncTaskOnThread(base::OnceCallback<T()> task,
                               scoped_refptr<cros::Future<T>> future) {
    future->Set(std::move(task).Run());
  }

  template <typename T>
  void ProcessAsyncTaskOnThread(base::OnceCallback<T()> task) {
    std::move(task).Run();
  }

  void ProcessClosureSyncTaskOnThread(
      base::OnceClosure task, scoped_refptr<cros::Future<void>> future) {
    std::move(task).Run();
    future->Set();
  }

  base::Thread thread_;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_THREAD_H_
