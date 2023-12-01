// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/event_dispatcher.h"

#include <utility>

#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>

namespace shill {

EventDispatcher::EventDispatcher() = default;

EventDispatcher::~EventDispatcher() = default;

void EventDispatcher::DispatchForever() {
  base::RunLoop run_loop;
  quit_closure_ = run_loop.QuitWhenIdleClosure();
  run_loop.Run();
}

void EventDispatcher::DispatchPendingEvents() {
  base::RunLoop().RunUntilIdle();
}

void EventDispatcher::PostTask(const base::Location& location,
                               base::OnceClosure task) {
  PostDelayedTask(FROM_HERE, std::move(task), base::TimeDelta());
}

void EventDispatcher::PostDelayedTask(const base::Location& location,
                                      base::OnceClosure task,
                                      base::TimeDelta delay) {
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      location, std::move(task), delay);
}

void EventDispatcher::QuitDispatchForever() {
  PostTask(FROM_HERE, quit_closure_);
}

}  // namespace shill
