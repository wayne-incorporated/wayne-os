// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/file_change_watcher.h"

#include <map>
#include <utility>
#include <vector>

#include <sys/inotify.h>
#include <sys/ioctl.h>

#include "base/files/scoped_file.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/posix/eintr_wrapper.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"

#include <base/check.h>
#include <base/check_op.h>

namespace croslog {

namespace {

// ============================================================================
// InotifyReaderThread

class InotifyReaderThread : public base::PlatformThread::Delegate {
 public:
  class Delegate {
   public:
    virtual void OnChanged(int inotify_wd, uint32_t mask) = 0;
  };

  // Must be called on the main thread.
  InotifyReaderThread(scoped_refptr<base::SequencedTaskRunner> task_runner,
                      Delegate* delegate)
      : task_runner_(std::move(task_runner)), delegate_(delegate) {
    DCHECK(delegate_);
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
  }

  // Must be called on the main thread.
  void StartThread(int inotify_fd) {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    inotify_fd_ = inotify_fd;

    CHECK(base::PlatformThread::CreateNonJoinable(0, this));
  }

 private:
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  int inotify_fd_ = -1;
  Delegate* const delegate_;

  // Must be called on the worker thread.
  void ThreadMain() {
    DCHECK(!task_runner_->RunsTasksInCurrentSequence());
    base::PlatformThread::SetName("inotify_reader");

    RunLoop();

    // The code after RunLoop() won't be executed except for error cases.
    // TODO(yoshiki): Shutdown this thread gracefully,
    LOG(ERROR) << "Failed to wait for file change events.";
  }

  // Must be called on the worker thread.
  void RunLoop() {
    DCHECK(!task_runner_->RunsTasksInCurrentSequence());

    // Make sure the file descriptors are good for use with select().
    // TODO(yoshiki): Use epoll(2) or base::FileDescriptorWatcher instead.
    CHECK_LE(0, inotify_fd_);
    CHECK_GT(FD_SETSIZE, inotify_fd_);

    while (true) {
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(inotify_fd_, &rfds);

      // Wait until some inotify events are available.
      int select_result = HANDLE_EINTR(
          select(inotify_fd_ + 1, &rfds, nullptr, nullptr, nullptr));
      if (select_result < 0) {
        DPLOG(WARNING) << "select failed";
        return;
      }

      // Adjust buffer size to current event queue size.
      int buffer_size;
      int ioctl_result =
          HANDLE_EINTR(ioctl(inotify_fd_, FIONREAD, &buffer_size));

      if (ioctl_result != 0) {
        DPLOG(WARNING) << "ioctl failed";
        return;
      }

      std::vector<char> buffer(buffer_size);

      ssize_t bytes_read =
          HANDLE_EINTR(read(inotify_fd_, &buffer[0], buffer_size));

      if (bytes_read < 0) {
        DPLOG(WARNING) << "read from inotify fd failed";
        return;
      }

      ssize_t i = 0;
      while (i < bytes_read) {
        inotify_event* event = reinterpret_cast<inotify_event*>(&buffer[i]);
        size_t event_size = sizeof(inotify_event) + event->len;
        DCHECK(i + event_size <= static_cast<size_t>(bytes_read));

        PostInotifyEvent(event);

        i += event_size;
      }
    }
  }

  // Must be called on the worker thread.
  void PostInotifyEvent(inotify_event* event) {
    DCHECK(!task_runner_->RunsTasksInCurrentSequence());

    // This method is invoked on the Inotify thread. Switch to task_runner() to
    // access |watches_| safely. Use a WeakPtr to prevent the callback from
    // running after |this| is destroyed (i.e. after the watch is cancelled).
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&Delegate::OnChanged, base::Unretained(delegate_),
                       event->wd, event->mask));
  }
};

// ============================================================================
// FileChangeWatcherImpl

class FileChangeWatcherImpl : public FileChangeWatcher,
                              public InotifyReaderThread::Delegate {
 public:
  FileChangeWatcherImpl()
      : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
        thread_(task_runner_, this) {
    // TODO(yoshiki): Handle log rotate.

    inotify_fd_.reset(inotify_init());
    PCHECK(inotify_fd_.is_valid()) << "inotify_init() failed";

    thread_.StartThread(inotify_fd_.get());
  }
  FileChangeWatcherImpl(const FileChangeWatcherImpl&) = delete;
  FileChangeWatcherImpl& operator=(const FileChangeWatcherImpl&) = delete;

  // Note: This class is initialized with base::NoDestructor so its destructor
  // is never called.

  bool AddWatch(const base::FilePath& path,
                FileChangeWatcher::Observer* observer) override {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());
    DCHECK(observer != nullptr);

    int inotify_wd = inotify_add_watch(inotify_fd_.get(), path.value().c_str(),
                                       IN_MODIFY | IN_MOVE_SELF);

    if (inotify_wd == -1) {
      DPLOG(ERROR) << "inotify_add_watch (" << path << ") failed";
      return false;
    }

    CHECK(watchers_inotify_.find(path) == watchers_inotify_.end());
    CHECK(watchers_observer_.find(inotify_wd) == watchers_observer_.end());

    watchers_inotify_[path] = inotify_wd;
    watchers_observer_[inotify_wd] = observer;

    return true;
  }

  void RemoveWatch(const base::FilePath& path) override {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());

    if (watchers_inotify_.find(path) == watchers_inotify_.end()) {
      LOG(WARNING) << "Unable to remove path: " << path << " is not added.";
      return;
    }

    int inotify_wd = watchers_inotify_[path];

    CHECK(watchers_observer_.find(inotify_wd) != watchers_observer_.end());
    watchers_observer_.erase(inotify_wd);
    watchers_inotify_.erase(path);

    auto inotify_wd_it =
        std::find(unexpectedly_removed_inotify_wds_.begin(),
                  unexpectedly_removed_inotify_wds_.end(), inotify_wd);
    bool already_removed_unexpectedly =
        inotify_wd_it != unexpectedly_removed_inotify_wds_.end();

    int ret = inotify_rm_watch(inotify_fd_.get(), inotify_wd);
    if (ret == -1 && !already_removed_unexpectedly)
      DPLOG(WARNING) << "inotify_rm_watch (" << path << ") failed";

    if (already_removed_unexpectedly)
      unexpectedly_removed_inotify_wds_.erase(inotify_wd_it);
  }

 private:
  base::ScopedFD inotify_fd_;
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  InotifyReaderThread thread_;

  std::map<base::FilePath, int> watchers_inotify_;
  std::map<int, FileChangeWatcher::Observer*> watchers_observer_;
  std::vector<int> unexpectedly_removed_inotify_wds_;

  void OnChanged(int inotify_wd, uint32_t mask) override {
    DCHECK(task_runner_->RunsTasksInCurrentSequence());

    // |inotify_wd| is negative if the event queue is overflowed.
    if (inotify_wd == -1) {
      for (auto&& i : watchers_observer_) {
        auto&& callback = i.second;
        callback->OnFileContentMaybeChanged();
        callback->OnFileNameMaybeChanged();
      }
      return;
    }
    if (watchers_observer_.find(inotify_wd) == watchers_observer_.end()) {
      // Timing issue. Maybe the inotify observer was removed but some
      // remaining event have been queued. Ignore them.
      return;
    }

    if (mask & IN_MODIFY) {
      auto&& delegate = watchers_observer_[inotify_wd];
      delegate->OnFileContentMaybeChanged();
    }

    if (mask & IN_MOVE_SELF) {
      auto&& delegate = watchers_observer_[inotify_wd];
      delegate->OnFileNameMaybeChanged();

      // Don't remove and add the inotify here. The user will do that, since
      // new file is unlikely to be created yet at this point.
    }

    if (mask & IN_IGNORED) {
      if (watchers_observer_.find(inotify_wd) != watchers_observer_.end()) {
        LOG(WARNING) << "The inofity has been removed unexpectedly (maybe the "
                        "file was removed?).";
        unexpectedly_removed_inotify_wds_.push_back(inotify_wd);
      }
    }
  }
};

}  // anonymous namespace

// ============================================================================
// FileChangeWatcher

// static
FileChangeWatcher* FileChangeWatcher::GetInstance() {
  static base::NoDestructor<FileChangeWatcherImpl> change_watcher;
  return change_watcher.get();
}

FileChangeWatcher::FileChangeWatcher() = default;

}  // namespace croslog
