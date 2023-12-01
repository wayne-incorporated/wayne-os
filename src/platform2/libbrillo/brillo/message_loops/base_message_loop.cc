// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/message_loops/base_message_loop.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __ANDROID_HOST__
// Used for MISC_MAJOR. Only required for the target and not always available
// for the host.
#include <linux/major.h>
#endif

#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/task/single_thread_task_runner.h>

#include <brillo/location_logging.h>
#include <brillo/strings/string_utils.h>

namespace {

const char kMiscMinorPath[] = "/proc/misc";
const char kBinderDriverName[] = "binder";

}  // namespace

namespace brillo {

const int BaseMessageLoop::kInvalidMinor = -1;
const int BaseMessageLoop::kUninitializedMinor = -2;

BaseMessageLoop::BaseMessageLoop() {
  CHECK(!base::SingleThreadTaskRunner::HasCurrentDefault())
      << "You can't create a base::SingleThreadTaskExecutor when another "
         "base::SingleThreadTaskExecutor is already created for this thread.";
  owned_task_executor_.reset(
      new base::SingleThreadTaskExecutor(base::MessagePumpType::IO));
  task_runner_ = owned_task_executor_->task_runner();
  watcher_ = std::make_unique<base::FileDescriptorWatcher>(task_runner_);
}

BaseMessageLoop::BaseMessageLoop(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(task_runner),
      watcher_(std::make_unique<base::FileDescriptorWatcher>(task_runner)) {}

BaseMessageLoop::~BaseMessageLoop() {
  // Note all pending canceled delayed tasks when destroying the message loop.
  size_t lazily_deleted_tasks = 0;
  for (const auto& delayed_task : delayed_tasks_) {
    if (delayed_task.second.closure.is_null()) {
      lazily_deleted_tasks++;
    } else {
      DVLOG_LOC(delayed_task.second.location, 1)
          << "Removing delayed task_id " << delayed_task.first
          << " leaked on BaseMessageLoop, scheduled from this location.";
    }
  }
  if (lazily_deleted_tasks) {
    LOG(INFO) << "Leaking " << lazily_deleted_tasks << " canceled tasks.";
  }
}

MessageLoop::TaskId BaseMessageLoop::PostDelayedTask(
    const base::Location& from_here,
    base::OnceClosure task,
    base::TimeDelta delay) {
  TaskId task_id = NextTaskId();
  bool base_scheduled = task_runner_->PostDelayedTask(
      from_here,
      base::BindOnce(&BaseMessageLoop::OnRanPostedTask,
                     weak_ptr_factory_.GetWeakPtr(), task_id),
      delay);
  DVLOG_LOC(from_here, 1) << "Scheduling delayed task_id " << task_id
                          << " to run in " << delay << ".";
  if (!base_scheduled)
    return MessageLoop::kTaskIdNull;

  delayed_tasks_.emplace(task_id,
                         DelayedTask{from_here, task_id, std::move(task)});
  return task_id;
}

bool BaseMessageLoop::CancelTask(TaskId task_id) {
  if (task_id == kTaskIdNull)
    return false;
  auto delayed_task_it = delayed_tasks_.find(task_id);
  if (delayed_task_it == delayed_tasks_.end())
    return false;

  // A DelayedTask was found for this task_id at this point.

  // Check if the callback was already canceled but we have the entry in
  // delayed_tasks_ since it didn't fire yet in the message loop.
  if (delayed_task_it->second.closure.is_null())
    return false;

  DVLOG_LOC(delayed_task_it->second.location, 1)
      << "Removing task_id " << task_id << " scheduled from this location.";
  // We reset to closure to a null OnceClosure to release all the resources
  // used by this closure at this point, but we don't remove the task_id from
  // delayed_tasks_ since we can't tell base::SingleThreadTaskExecutor to not
  // run it.
  delayed_task_it->second.closure.Reset();

  return true;
}

bool BaseMessageLoop::RunOnce(bool may_block) {
  run_once_ = true;
  // Uses the base::SingleThreadTaskExecutor implicitly.
  base::RunLoop run_loop;
  base_run_loop_ = &run_loop;
  if (!may_block)
    run_loop.RunUntilIdle();
  else
    run_loop.Run();
  base_run_loop_ = nullptr;
  // If the flag was reset to false, it means a closure was run.
  if (!run_once_)
    return true;

  run_once_ = false;
  return false;
}

void BaseMessageLoop::Run() {
  // Uses the base::SingleThreadTaskExecutor implicitly.
  base::RunLoop run_loop;
  base_run_loop_ = &run_loop;
  run_loop.Run();
  base_run_loop_ = nullptr;
}

void BaseMessageLoop::BreakLoop() {
  if (base_run_loop_ == nullptr) {
    DVLOG(1) << "Message loop not running, ignoring BreakLoop().";
    return;  // Message loop not running, nothing to do.
  }
  base_run_loop_->Quit();
}

base::RepeatingClosure BaseMessageLoop::QuitClosure() const {
  if (base_run_loop_ == nullptr)
    return base::DoNothing();
  return base_run_loop_->QuitClosure();
}

MessageLoop::TaskId BaseMessageLoop::NextTaskId() {
  TaskId res;
  do {
    res = ++last_id_;
    // We would run out of memory before we run out of task ids.
  } while (!res || delayed_tasks_.find(res) != delayed_tasks_.end());
  return res;
}

void BaseMessageLoop::OnRanPostedTask(MessageLoop::TaskId task_id) {
  auto task_it = delayed_tasks_.find(task_id);
  DCHECK(task_it != delayed_tasks_.end());
  if (!task_it->second.closure.is_null()) {
    DVLOG_LOC(task_it->second.location, 1)
        << "Running delayed task_id " << task_id
        << " scheduled from this location.";
    // Mark the task as canceled while we are running it so CancelTask returns
    // false.
    std::move(task_it->second.closure).Run();

    // If the |run_once_| flag is set, it is because we are instructed to run
    // only once callback.
    if (run_once_) {
      run_once_ = false;
      BreakLoop();
    }
  }
  delayed_tasks_.erase(task_it);
}

int BaseMessageLoop::ParseBinderMinor(const std::string& file_contents) {
  int result = kInvalidMinor;
  // Split along '\n', then along the ' '. Note that base::SplitString trims all
  // white spaces at the beginning and end after splitting.
  std::vector<std::string> lines = base::SplitString(
      file_contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const std::string& line : lines) {
    if (line.empty())
      continue;
    std::string number;
    std::string name;
    if (!string_utils::SplitAtFirst(line, " ", &number, &name, false))
      continue;

    if (name == kBinderDriverName && base::StringToInt(number, &result))
      break;
  }
  return result;
}

unsigned int BaseMessageLoop::GetBinderMinor() {
  if (binder_minor_ != kUninitializedMinor)
    return binder_minor_;

  std::string proc_misc;
  if (!base::ReadFileToString(base::FilePath(kMiscMinorPath), &proc_misc))
    return binder_minor_;
  binder_minor_ = ParseBinderMinor(proc_misc);
  return binder_minor_;
}

}  // namespace brillo
