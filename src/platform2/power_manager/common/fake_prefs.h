// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_COMMON_FAKE_PREFS_H_
#define POWER_MANAGER_COMMON_FAKE_PREFS_H_

#include <stdint.h>

#include <map>
#include <string>
#include <utility>

#include <base/compiler_specific.h>

#include "power_manager/common/prefs.h"

namespace power_manager {

// Fake implementation of PrefsInterface for tests that just stores prefs
// in-memory.
class FakePrefs : public PrefsInterface {
 public:
  FakePrefs() = default;
  FakePrefs(const FakePrefs&) = delete;
  FakePrefs& operator=(const FakePrefs&) = delete;

  ~FakePrefs() override = default;

  // Deletes |name| from |*_prefs_|.
  void Unset(const std::string& name);

  // Notifies |observers_| that a pref has changed.
  void NotifyObservers(const std::string& name);

  // PrefsInterface implementation:
  void AddObserver(PrefsObserver* observer) override;
  void RemoveObserver(PrefsObserver* observer) override;
  bool GetString(const std::string& name, std::string* value) override;
  bool GetInt64(const std::string& name, int64_t* value) override;
  bool GetDouble(const std::string& name, double* value) override;
  bool GetBool(const std::string& name, bool* value) override;
  void SetString(const std::string& name, const std::string& value) override;
  void SetInt64(const std::string& name, int64_t value) override;
  void SetDouble(const std::string& name, double value) override;
  void SetBool(const std::string& name, bool value) override;
  bool GetExternalString(const std::string& path,
                         const std::string& name,
                         std::string* value) override;

  void set_external_string_for_testing(const std::string& path,
                                       const std::string& name,
                                       const std::string& value);

 private:
  base::ObserverList<PrefsObserver> observers_;

  std::map<std::string, int64_t> int64_prefs_;
  std::map<std::string, double> double_prefs_;
  std::map<std::string, std::string> string_prefs_;
  std::map<std::pair<std::string, std::string>, std::string> external_prefs_;
};

}  // namespace power_manager

#endif  // POWER_MANAGER_COMMON_FAKE_PREFS_H_
