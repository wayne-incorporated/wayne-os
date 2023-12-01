// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_HANDLE_GENERATOR_H_
#define CHAPS_HANDLE_GENERATOR_H_

namespace chaps {

// A HandleGenerator simply generates unique handles.
class HandleGenerator {
 public:
  virtual ~HandleGenerator() {}
  virtual int CreateHandle() = 0;
};

}  // namespace chaps

#endif  // CHAPS_HANDLE_GENERATOR_H_
