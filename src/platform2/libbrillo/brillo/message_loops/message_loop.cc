// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/message_loops/message_loop.h>

#include <absl/base/attributes.h>
#include <base/check.h>
#include <base/lazy_instance.h>
#include <base/logging.h>
#include <base/threading/thread_local.h>

namespace brillo {

namespace {

// A lazily created thread local storage for quick access to a thread's message
// loop, if one exists.  This should be safe and free of static constructors.
ABSL_CONST_INIT thread_local MessageLoop* lazy_tls_ptr = nullptr;

}  // namespace

const MessageLoop::TaskId MessageLoop::kTaskIdNull = 0;

MessageLoop* MessageLoop::current() {
  DCHECK(lazy_tls_ptr != nullptr)
      << "There isn't a MessageLoop for this thread. You need to initialize it "
         "first.";
  return lazy_tls_ptr;
}

bool MessageLoop::ThreadHasCurrent() {
  return lazy_tls_ptr != nullptr;
}

void MessageLoop::SetAsCurrent() {
  DCHECK(lazy_tls_ptr == nullptr)
      << "There's already a MessageLoop for this thread.";
  lazy_tls_ptr = this;
}

void MessageLoop::ReleaseFromCurrent() {
  DCHECK(lazy_tls_ptr == this)
      << "This is not the MessageLoop bound to the current thread.";
  lazy_tls_ptr = nullptr;
}

MessageLoop::~MessageLoop() {
  if (lazy_tls_ptr == this)
    lazy_tls_ptr = nullptr;
}

void MessageLoop::Run() {
  // Default implementation is to call RunOnce() blocking until there aren't
  // more tasks scheduled.
  while (!should_exit_ && RunOnce(true)) {
  }
  should_exit_ = false;
}

void MessageLoop::BreakLoop() {
  should_exit_ = true;
}

}  // namespace brillo
