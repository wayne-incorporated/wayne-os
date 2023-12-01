// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_ERROR_ACTION_H_
#define CRYPTOHOME_ERROR_ACTION_H_

#include <set>

#include <base/logging.h>

namespace cryptohome {

namespace error {

// PrimaryActions are actions that cryptohome is sure about why the error
// happened. Therefore when a primary actions is specified, no other possible
// actions will be included in the error info. Check the ActionsFromStack
// function to see how we determine the correct primary action when there are
// more than one in the chain.
enum class PrimaryAction {
  // Note that this enum is reordered compared to when PrimaryAction and
  // PossibleAction were in the same enum. Please refer to old code if you want
  // to understand cryptohome error logs from previous versions.
  kTpmUpdateRequired,
  kTpmLockout,
  kIncorrectAuth,
  kLeLockedOut,
  kLeExpired,
  kMaxValue = kLeExpired,
};

constexpr size_t kPrimaryActionEnumSize =
    static_cast<size_t>(PrimaryAction::kMaxValue) + 1;

// PossibleAction are actions that cryptohome isn't sure about why the error
// happened, but recommends some possible actions that might fix the error. All
// possible actions are included in the error info when there are no primary
// actions.
enum class PossibleAction {
  kRetry,
  kReboot,
  kAuth,
  kDeleteVault,
  kPowerwash,
  kDevCheckUnexpectedState,
  kFatal,
  kMaxValue = kFatal,
};

constexpr size_t kPossibleActionEnumSize =
    static_cast<size_t>(PossibleAction::kMaxValue) + 1;

class PossibleActions : public std::bitset<kPossibleActionEnumSize> {
 public:
  PossibleActions() = default;
  explicit PossibleActions(std::initializer_list<PossibleAction> init) {
    for (PossibleAction action : init) {
      operator[](action) = true;
    }
  }

  using std::bitset<kPossibleActionEnumSize>::operator[];

  bool operator[](PossibleAction pos) const {
    return bitset::operator[](static_cast<size_t>(pos));
  }
  reference operator[](PossibleAction pos) {
    return bitset::operator[](static_cast<size_t>(pos));
  }
};

// ErrorActionSet describes the actions attached in a cryptohome error location.
// It may be either a primary action or a set of possible actions.
class ErrorActionSet : public std::variant<PrimaryAction, PossibleActions> {
 public:
  using std::variant<PrimaryAction, PossibleActions>::variant;
  // This constructor is needed to allow the
  // ErrorActionSet({PossibleAction::X, PossibleAction::Y}) syntax.
  ErrorActionSet(std::initializer_list<PossibleAction> init)
      : ErrorActionSet(PossibleActions(init)) {}
};

inline ErrorActionSet NoErrorAction() {
  return PossibleActions{};
}

}  // namespace error

}  // namespace cryptohome

#endif  // CRYPTOHOME_ERROR_ACTION_H_
