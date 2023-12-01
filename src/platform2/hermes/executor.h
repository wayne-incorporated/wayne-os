// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_EXECUTOR_H_
#define HERMES_EXECUTOR_H_

#include <base/memory/scoped_refptr.h>
#include <base/task/single_thread_task_runner.h>
#include <google-lpa/lpa/util/executor.h>

namespace hermes {

// Class to allow an arbitrary std::function<void()> to be executed on the
// thread of the provided MessageLoop.
class Executor : public lpa::util::Executor {
 public:
  explicit Executor(scoped_refptr<base::SingleThreadTaskRunner> task_runner);
  void Execute(std::function<void()> f) override;
  virtual void PostDelayedTask(const base::Location& from_here,
                               base::OnceClosure task,
                               base::TimeDelta delay);

 protected:
  // Used by MockExecutor to forward time
  const scoped_refptr<base::SingleThreadTaskRunner>& task_runner() const {
    return task_runner_;
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
};

}  // namespace hermes

#endif  // HERMES_EXECUTOR_H_
