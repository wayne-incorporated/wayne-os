// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/executor.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>

namespace hermes {

Executor::Executor(scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : task_runner_(task_runner) {
  CHECK(task_runner_);
}

void Executor::Execute(std::function<void()> f) {
  // TaskRunner::PostTask takes a base::OnceClosure, not a std::function.
  // Convert the captureless lambda into a base::BindState for use as a
  // base::OnceClosure.
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce([](std::function<void()> f) { f(); }, std::move(f)));
}

void Executor::PostDelayedTask(const base::Location& from_here,
                               base::OnceClosure task,
                               base::TimeDelta delay) {
  task_runner_->PostDelayedTask(from_here, std::move(task), delay);
}

}  // namespace hermes
