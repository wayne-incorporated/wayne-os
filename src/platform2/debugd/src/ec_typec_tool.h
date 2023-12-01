// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_EC_TYPEC_TOOL_H_
#define DEBUGD_SRC_EC_TYPEC_TOOL_H_

#include <string>

#include <brillo/errors/error.h>
#include <gtest/gtest_prod.h>

namespace debugd {

class EcTypeCTool {
 public:
  EcTypeCTool() = default;
  EcTypeCTool(const EcTypeCTool&) = delete;
  EcTypeCTool& operator=(const EcTypeCTool&) = delete;

  ~EcTypeCTool() = default;

  std::string GetInventory();
  bool EnterMode(brillo::ErrorPtr* error,
                 uint32_t port_num,
                 uint32_t mode,
                 std::string* output);
  bool ExitMode(brillo::ErrorPtr* error,
                uint32_t port_num,
                std::string* output);
  bool DpState(brillo::ErrorPtr* error, uint32_t port_num, bool* output);
  bool HpdState(brillo::ErrorPtr* error, uint32_t port_num, bool* output);

 private:
  friend class EcTypeCToolTest;
  FRIEND_TEST(EcTypeCToolTest, DpStateTest);
  FRIEND_TEST(EcTypeCToolTest, HpdStateTest);

  // Internal helper functions that parse DP and HPD state. This allows the
  // logic to be unit tested without having to mock out ectool calls.
  bool ParseDpState(brillo::ErrorPtr* error,
                    uint32_t port_num,
                    const std::string& input,
                    bool* output);
  bool ParseHpdState(brillo::ErrorPtr* error,
                     uint32_t port_num,
                     const std::string& input,
                     bool* output);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_EC_TYPEC_TOOL_H_
