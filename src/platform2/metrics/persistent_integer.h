// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_PERSISTENT_INTEGER_H_
#define METRICS_PERSISTENT_INTEGER_H_

#include <stdint.h>

#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/strings/string_piece.h>

namespace chromeos_metrics {

// PersistentIntegers is a 64-bit integer value backed by a file.
// The in-memory value acts as a write-through cache of the file value.
// If the backing file doesn't exist or has bad content, the value is 0.

class PersistentInteger {
 public:
  // |backing_file_path| is the path to a file that is created, read and
  // written in order to preserves the integer value across restarts of the
  // program using it.  The directory of the file must exist.
  explicit PersistentInteger(const base::FilePath& backing_file_path);
  PersistentInteger(const PersistentInteger&) = delete;
  PersistentInteger& operator=(const PersistentInteger&) = delete;

  // Virtual only because of mock.
  virtual ~PersistentInteger();

  // Sets the value.  This writes through to the backing file.
  void Set(int64_t v);

  // Gets the value.  May sync from backing file first.
  int64_t Get();

  // Convenience function for Get() followed by Set(0).
  // Virtual only because of mock.
  virtual int64_t GetAndClear();

  // Convenience function for v = Get, Set(v + x).
  // Virtual only because of mock.
  virtual void Add(int64_t x);

  // Convenience function for v = Get, Set(max(v, x)).
  // Virtual only because of mock.
  virtual void Max(int64_t x);

  // Set a callback that is called each time a PersistentInteger is created.
  static void SetCreationCallbackForTesting(
      const base::RepeatingCallback<void(const base::FilePath&)>&
          creation_callback);
  static void ClearCreationCallbackForTesting();

 private:
  static const int kVersion = 1001;

  // Writes |value_| to the backing file, creating it if necessary.
  void Write();

  // Reads the value from the backing file, stores it in |value_|, and returns
  // true if the backing file is valid.  Returns false otherwise, and creates
  // a valid backing file as a side effect.
  bool Read();

  base::FilePath path_;
  bool synced_;
  int64_t value_;
  int32_t version_;

  static bool testing_;
};

}  // namespace chromeos_metrics

#endif  // METRICS_PERSISTENT_INTEGER_H_
