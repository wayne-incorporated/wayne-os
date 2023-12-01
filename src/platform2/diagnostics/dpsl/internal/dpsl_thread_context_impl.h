// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_DPSL_THREAD_CONTEXT_IMPL_H_
#define DIAGNOSTICS_DPSL_INTERNAL_DPSL_THREAD_CONTEXT_IMPL_H_

#include <memory>

#include <base/memory/scoped_refptr.h>
#include <base/run_loop.h>
#include <base/sequence_checker_impl.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/platform_thread.h>

#include "diagnostics/dpsl/public/dpsl_thread_context.h"

namespace diagnostics {

// Real implementation of the DpslThreadContext interface.
class DpslThreadContextImpl final : public DpslThreadContext {
 public:
  // Cleans thread counter which prevents from calling
  // |DpslThreadContext::Create()| more than once per thread.
  static void CleanThreadCounterForTesting();

  DpslThreadContextImpl();
  DpslThreadContextImpl(const DpslThreadContextImpl&) = delete;
  DpslThreadContextImpl& operator=(const DpslThreadContextImpl&) = delete;

  ~DpslThreadContextImpl() override;

  // DpslThreadContext overrides:
  bool BelongsToCurrentThread() override;
  void RunEventLoop() override;
  bool IsEventLoopRunning() override;
  void PostTask(std::function<void()> task) override;
  void PostDelayedTask(std::function<void()> task,
                       int64_t delay_milliseconds) override;
  void QuitEventLoop() override;

 private:
  // Identifier of the thread which is associated with this instance.
  const base::PlatformThreadId thread_id_;
  // SingleThreadTaskExecutor owned by this instance. Only gets created when no
  // previously created task runner was present at construction time.
  std::unique_ptr<base::SingleThreadTaskExecutor> owned_task_executor_;
  // Task runner of the thread associated with this instance.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  // The run loop which is used for the current invocation of RunEventLoop(). Is
  // null when this method is not currently run.
  base::RunLoop* current_run_loop_ = nullptr;

  base::SequenceCheckerImpl sequence_checker_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_DPSL_THREAD_CONTEXT_IMPL_H_
