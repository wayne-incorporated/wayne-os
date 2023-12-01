// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_UTIL_DYNAMIC_FLAG_H_
#define MISSIVE_UTIL_DYNAMIC_FLAG_H_

#include <atomic>
#include <string>

#include <base/strings/string_piece.h>

namespace reporting {

// Class represents an atomic boolean flag.
// The flag is initialized and then can be queried and/or updated.
// Can be subclassed or aggregated by the owner class.
class DynamicFlag {
 public:
  DynamicFlag(base::StringPiece name, bool is_enabled);
  DynamicFlag(const DynamicFlag&) = delete;
  DynamicFlag& operator=(const DynamicFlag&) = delete;
  virtual ~DynamicFlag();

  // Returns current value of the flag.
  bool is_enabled() const;

  // Sets flag's value.
  void SetValue(bool is_enabled);

 private:
  // Called when the flag's value changes, getting the new value.
  // Does nothing by default, can be overridden by the subclass.
  // Note that an attempt to read the current value by calling `is_enabled()`
  // instead of the `is_enabled` argument creates a race condition: they may
  // return different values, if `SetValue` happened to be called in a meantime.
  // For this reason it is recommended to either use `is_enabled()` or
  // `OnValueUpdate` but not both in the same class.
  virtual void OnValueUpdate(bool is_enabled);

  const std::string name_;
  std::atomic<bool> is_enabled_;
};
}  // namespace reporting

#endif  // MISSIVE_UTIL_DYNAMIC_FLAG_H_
