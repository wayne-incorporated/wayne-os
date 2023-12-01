// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <ostream>

#include "hermes/euicc_event.h"

namespace hermes {

EuiccEvent::EuiccEvent(uint32_t slot, EuiccStep step, EuiccOp op)
    : slot(slot), step(step), op(op) {}

EuiccEvent::EuiccEvent(uint32_t slot, EuiccStep step)
    : slot(slot), step(step), op(EuiccOp::UNKNOWN) {}

std::ostream& operator<<(std::ostream& os, const EuiccStep& rhs) {
  switch (rhs) {
    case (EuiccStep::START):
      os << "START";
      break;
    case (EuiccStep::PENDING_NOTIFICATIONS):
      os << "PENDING_NOTIFICATIONS";
      break;
    case (EuiccStep::END):
      os << "END";
      break;
    default:
      os << rhs;
      break;
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, const EuiccOp& rhs) {
  switch (rhs) {
    case (EuiccOp::UNKNOWN):
      os << "UNKNOWN";
      break;
    case (EuiccOp::ENABLE):
      os << "ENABLE";
      break;
    case (EuiccOp::DISABLE):
      os << "DISABLE";
      break;
    case (EuiccOp::FW_UPDATE):
      os << "FW_UPDATE";
      break;
    case EuiccOp::INSTALL:
      os << "INSTALL";
      break;
    case EuiccOp::UNINSTALL:
      os << "UNINSTALL";
      break;
    case EuiccOp::REFRESH_INSTALLED:
      os << "REFRESH_INSTALLED";
      break;
    case EuiccOp::REQUEST_PENDING:
      os << "REQUEST_PENDING";
      break;
    case EuiccOp::INSTALL_PENDING:
      os << "INSTALL_PENDING";
      break;
    case EuiccOp::SET_TEST_MODE:
      os << "SET_TEST_MODE";
      break;
    case EuiccOp::RESET_MEMORY:
      os << "RESET_MEMORY";
      break;
    case EuiccOp::GET_EUICC_INFO1:
      os << "GET_EUICC_INFO1";
      break;
    case EuiccOp::RENAME:
      os << "RENAME";
      break;
    default:
      os << rhs;
      break;
  }
  return os;
}

std::ostream& operator<<(std::ostream& os, const EuiccEvent& rhs) {
  os << "Slot: " << rhs.slot << ", Step:" << rhs.step << ", Op:" << rhs.op;
  return os;
}

}  // namespace hermes
