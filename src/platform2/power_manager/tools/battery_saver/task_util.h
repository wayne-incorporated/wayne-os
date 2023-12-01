// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_TOOLS_BATTERY_SAVER_TASK_UTIL_H_
#define POWER_MANAGER_TOOLS_BATTERY_SAVER_TASK_UTIL_H_

#include <utility>

#include <base/functional/callback_forward.h>
#include <base/location.h>
#include <base/task/sequenced_task_runner.h>

namespace power_manager {

// Post a task to the current thread's SequencedTaskRunner.
//
// This is simply a short-hand way of writing:
//
//   base::SequencedTaskRunner::GetCurrentDefault()->PostTask(FROM_HERE, foo);
//
// which can instead be written as:
//
//   PostToCurrentSequence(foo);
//
inline bool PostToCurrentSequence(
    base::OnceClosure task,
    const base::Location& from_here = base::Location::Current()) {
  return base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      from_here, std::move(task));
}

}  // namespace power_manager

#endif  // POWER_MANAGER_TOOLS_BATTERY_SAVER_TASK_UTIL_H_
