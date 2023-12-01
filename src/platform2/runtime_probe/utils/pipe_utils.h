// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_PIPE_UTILS_H_
#define RUNTIME_PROBE_UTILS_PIPE_UTILS_H_

#include <string>
#include <vector>

namespace runtime_probe {

bool ReadNonblockingPipeToString(const std::vector<int>& fds,
                                 std::vector<std::string>* out);

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_PIPE_UTILS_H_
