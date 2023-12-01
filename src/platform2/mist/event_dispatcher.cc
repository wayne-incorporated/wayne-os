// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/event_dispatcher.h"

#include <utility>

#include <base/check_op.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>

namespace mist {

EventDispatcher::EventDispatcher()
    : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

EventDispatcher::~EventDispatcher() = default;

void EventDispatcher::DispatchForever() {
  base::RunLoop run_loop;
  quit_closure_ = run_loop.QuitWhenIdleClosure();
  run_loop.Run();
}

void EventDispatcher::Stop() {
  task_runner_->PostTask(FROM_HERE, std::move(quit_closure_));
}

bool EventDispatcher::PostTask(base::OnceClosure task) {
  return task_runner_->PostTask(FROM_HERE, std::move(task));
}

bool EventDispatcher::PostDelayedTask(base::OnceClosure task,
                                      const base::TimeDelta& delay) {
  return task_runner_->PostDelayedTask(FROM_HERE, std::move(task), delay);
}

}  // namespace mist
