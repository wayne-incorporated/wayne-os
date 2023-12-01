// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_FAKE_ACPI_WAKEUP_FILE_H_
#define POWER_MANAGER_POWERD_SYSTEM_FAKE_ACPI_WAKEUP_FILE_H_

#include <memory>
#include <string>

#include "gtest/gtest.h"

#include "power_manager/powerd/system/acpi_wakeup_helper.h"

namespace power_manager::system {

// Fake file implementation for use in unit tests and fuzzers.
class FakeAcpiWakeupFile : public AcpiWakeupFileInterface {
 public:
  FakeAcpiWakeupFile()
      : contents_(nullptr),
        expected_write_(nullptr),
        contents_after_write_(nullptr) {}

  bool Exists() override { return contents_ != nullptr; }

  bool Read(std::string* contents) override {
    if (!contents_)
      return false;
    *contents = *contents_;
    return true;
  }

  bool Write(const std::string& contents) override {
    if (!expected_write_ || contents != *expected_write_) {
      ADD_FAILURE() << "Unexpected write";
      return false;
    }
    *contents_ = *contents_after_write_;
    expected_write_.reset();
    contents_after_write_.reset();
    return true;
  }

  void set_contents(const char* contents) {
    contents_ = std::make_unique<std::string>(contents);
    expected_write_.reset();
    contents_after_write_.reset();
  }

  void ExpectWrite(const char* expected_write,
                   const char* contents_after_write) {
    expected_write_ = std::make_unique<std::string>(expected_write);
    contents_after_write_ = std::make_unique<std::string>(contents_after_write);
  }

  void Verify() {
    if (expected_write_) {
      ADD_FAILURE() << "Expected write did not happen";
    }
  }

 private:
  std::unique_ptr<std::string> contents_;
  std::unique_ptr<std::string> expected_write_;
  std::unique_ptr<std::string> contents_after_write_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_FAKE_ACPI_WAKEUP_FILE_H_
