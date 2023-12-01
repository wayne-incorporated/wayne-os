// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/udev/udev_list_entry.h>

#include <libudev.h>

#include <base/logging.h>

namespace brillo {

UdevListEntryImpl::UdevListEntryImpl(udev_list_entry* list_entry)
    : list_entry_(list_entry) {
  CHECK(list_entry_);
}

std::unique_ptr<UdevListEntry> UdevListEntryImpl::GetNext() const {
  udev_list_entry* list_entry = udev_list_entry_get_next(list_entry_);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

std::unique_ptr<UdevListEntry> UdevListEntryImpl::GetByName(
    const char* name) const {
  udev_list_entry* list_entry = udev_list_entry_get_by_name(list_entry_, name);
  return list_entry ? std::make_unique<UdevListEntryImpl>(list_entry) : nullptr;
}

const char* UdevListEntryImpl::GetName() const {
  return udev_list_entry_get_name(list_entry_);
}

const char* UdevListEntryImpl::GetValue() const {
  return udev_list_entry_get_value(list_entry_);
}

}  // namespace brillo
