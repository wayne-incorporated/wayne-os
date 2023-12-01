// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_UDEV_LIST_ENTRY_H_
#define LIBBRILLO_BRILLO_UDEV_UDEV_LIST_ENTRY_H_

#include <memory>

#include <brillo/brillo_export.h>

struct udev_list_entry;

namespace brillo {

// A udev list entry, which wraps a udev_list_entry C struct from libudev and
// related library functions into a C++ object.
class BRILLO_EXPORT UdevListEntry {
 public:
  virtual ~UdevListEntry() = default;

  // Wraps udev_list_entry_get_next().
  virtual std::unique_ptr<UdevListEntry> GetNext() const = 0;

  // Wraps udev_list_entry_get_by_name().
  virtual std::unique_ptr<UdevListEntry> GetByName(const char* name) const = 0;

  // Wraps udev_list_entry_get_name().
  virtual const char* GetName() const = 0;

  // Wraps udev_list_entry_get_value().
  virtual const char* GetValue() const = 0;
};

class BRILLO_EXPORT UdevListEntryImpl : public UdevListEntry {
 public:
  // Constructs a UdevListEntry object by taking a raw pointer to a
  // udev_list_entry struct as |list_entry|. The ownership of |list_entry| is
  // not transferred, and thus it should outlive this object.
  explicit UdevListEntryImpl(udev_list_entry* list_entry);

  UdevListEntryImpl(const UdevListEntryImpl&) = delete;
  UdevListEntryImpl& operator=(const UdevListEntryImpl&) = delete;

  // UdevListEntry overrides.
  std::unique_ptr<UdevListEntry> GetNext() const override;
  std::unique_ptr<UdevListEntry> GetByName(const char* name) const override;
  const char* GetName() const override;
  const char* GetValue() const override;

 private:
  udev_list_entry* const list_entry_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_UDEV_LIST_ENTRY_H_
