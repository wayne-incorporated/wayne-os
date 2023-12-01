// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_MIST_H_
#define MIST_MIST_H_

namespace base {

class CommandLine;

}  // namespace base

namespace mist {

class Mist {
 public:
  Mist() = default;
  Mist(const Mist&) = delete;
  Mist& operator=(const Mist&) = delete;

  ~Mist() = default;

  // Runs mist with the given command line. Returns the exit code. The ownership
  // of |command_line| is not transferred.
  int Run(base::CommandLine* command_line);
};

}  // namespace mist

#endif  // MIST_MIST_H_
