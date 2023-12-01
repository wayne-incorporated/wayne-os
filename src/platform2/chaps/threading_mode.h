// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_THREADING_MODE_H_
#define CHAPS_THREADING_MODE_H_

namespace chaps {

enum class ThreadingMode {
  // This mode will create an extra thread for the proxy.
  kStandaloneWorkerThread,

  // The middleware & backend will run on the current thread.
  kCurrentThread,
};

}  // namespace chaps

#endif  // CHAPS_THREADING_MODE_H_
