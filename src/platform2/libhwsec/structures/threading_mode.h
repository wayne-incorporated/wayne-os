// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_THREADING_MODE_H_
#define LIBHWSEC_STRUCTURES_THREADING_MODE_H_

namespace hwsec {

// Most of the factory implementations will support two kinds of threading
// modes.
//
// A simple rule to choose between these two modes:
//    If it's single thread environment, use kCurrentThread.
//    Otherwise, use kStandaloneWorkerThread.

enum class ThreadingMode {
  // This mode will create an extra thread for the underlying middleware and
  // backend, and the frontend interface will be thread safe.
  // This mode can be used in any case, the only downside of it is the
  // performance.
  kStandaloneWorkerThread,

  // The middleware & backend will run on the thread that created the
  // factory.
  // If current thread don't have task runner, the asynchronous will check
  // fail. This mode should only be used when the creation, destruction and
  // usage of the libhwsec is all on the same thread, otherwise it may result
  // race conditions or deadlocks.
  kCurrentThread,
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_THREADING_MODE_H_
