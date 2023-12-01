// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_DPSL_INTERNAL_TEST_DPSL_BACKGROUND_THREAD_H_
#define DIAGNOSTICS_DPSL_INTERNAL_TEST_DPSL_BACKGROUND_THREAD_H_

#include <functional>
#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/synchronization/waitable_event.h>
#include <base/threading/simple_thread.h>

namespace diagnostics {

class DpslGlobalContext;
class DpslThreadContext;

// TestDpslBackgroundThread is a wrapper for simplifying the usage of DPSL
// threading primitives in order to test other parts of DPSL.
// This class should only be used on the same thread on which it was created.
class TestDpslBackgroundThread final
    : public base::DelegateSimpleThread::Delegate {
 public:
  // Wraps |background_callback| to post |main_thread_callback| to
  // |main_thread_context| after |background_callback| was invoked.
  static std::function<void()> WrapTaskToReplyOnMainThread(
      base::OnceClosure background_callback,
      DpslThreadContext* main_thread_context,
      base::OnceClosure main_thread_callback);

  TestDpslBackgroundThread(const std::string& name,
                           DpslGlobalContext* global_context,
                           DpslThreadContext* main_thread_context);
  TestDpslBackgroundThread(const TestDpslBackgroundThread&) = delete;
  TestDpslBackgroundThread& operator=(const TestDpslBackgroundThread&) = delete;

  ~TestDpslBackgroundThread() override;

  // Starts background event loop. Must be called no more than once.
  void StartEventLoop();

  // Posts |background_callback| as a background task and waits until it will be
  // processed. |StartEventLoop()| must be called before.
  void DoSync(base::OnceClosure background_callback);

  DpslThreadContext* thread_context();

 private:
  // base::DelegateSimpleThread::Delegate overrides:
  void Run() override;

  std::function<void()> on_thread_context_ready_;

  DpslGlobalContext* const global_context_;
  DpslThreadContext* const main_thread_context_;

  std::unique_ptr<DpslThreadContext> thread_context_;

  // Used inside the background thread to wait the signal to run event loop in
  // the background thread.
  base::WaitableEvent run_event_loop_event_;

  base::DelegateSimpleThread thread_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_DPSL_INTERNAL_TEST_DPSL_BACKGROUND_THREAD_H_
