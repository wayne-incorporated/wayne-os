// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_FAKE_UDEV_LIST_H_
#define LIBBRILLO_BRILLO_UDEV_FAKE_UDEV_LIST_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <brillo/brillo_export.h>
#include <brillo/udev/udev_list_entry.h>

namespace brillo {

class BRILLO_EXPORT NameValuePair {
 public:
  NameValuePair(std::string name, std::optional<std::string> value);
  ~NameValuePair();

  const char* GetName() const;
  const char* GetValue() const;

 private:
  std::string name_;
  std::optional<std::string> value_;
};

// FakeUdevList will supply a list of name-value pairs that can be used in
// e.g. fake implementations of UdevDevice::GetPropertiesListEntry, and
// other methods that wrap libudev functions returning udev_list_entry*.
//
// The lifetime of the returned Entries should not be longer than the
// FakeUdevList they point into, as they do not hold a strong reference to
// the parent FakeUdevList.
class BRILLO_EXPORT FakeUdevList {
 public:
  explicit FakeUdevList(std::vector<NameValuePair> entries);
  ~FakeUdevList();

  std::unique_ptr<UdevListEntry> GetFirstEntry() const;

 private:
  class Entry : public UdevListEntry {
   public:
    Entry(const FakeUdevList* list, int index);
    ~Entry() override;

    // UdevListEntry overrides.
    std::unique_ptr<UdevListEntry> GetNext() const override;
    std::unique_ptr<UdevListEntry> GetByName(const char* name) const override;
    const char* GetName() const override;
    const char* GetValue() const override;

   private:
    const FakeUdevList* list_;
    int index_;
  };

  std::vector<NameValuePair> entries_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_FAKE_UDEV_LIST_H_
