// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_EUICC_EVENT_H_
#define HERMES_EUICC_EVENT_H_

namespace hermes {

enum class EuiccStep {
  START,
  PENDING_NOTIFICATIONS,
  END,
};

enum class EuiccOp {
  UNKNOWN,
  DISABLE,
  ENABLE,
  FW_UPDATE,
  INSTALL,
  UNINSTALL,
  REFRESH_INSTALLED,
  REQUEST_PENDING,
  INSTALL_PENDING,
  SET_TEST_MODE,
  RESET_MEMORY,
  GET_EUICC_INFO1,
  RENAME,
};

struct EuiccEvent {
  uint32_t slot;
  EuiccStep step;
  EuiccOp op;

  EuiccEvent(uint32_t slot, EuiccStep step);
  EuiccEvent(uint32_t slot, EuiccStep step, EuiccOp op);
};

std::ostream& operator<<(std::ostream& os, const EuiccStep& rhs);
std::ostream& operator<<(std::ostream& os, const EuiccOp& rhs);
std::ostream& operator<<(std::ostream& os, const EuiccEvent& rhs);

}  // namespace hermes

#endif  // HERMES_EUICC_EVENT_H_
