// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_CONTAINER_TOOL_H_
#define DEBUGD_SRC_CONTAINER_TOOL_H_

namespace debugd {

class ContainerTool {
 public:
  ContainerTool() = default;
  ContainerTool(const ContainerTool&) = delete;
  ContainerTool& operator=(const ContainerTool&) = delete;

  ~ContainerTool() = default;

  void ContainerStarted();
  void ContainerStopped();

 private:
  bool device_jail_started_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_CONTAINER_TOOL_H_
