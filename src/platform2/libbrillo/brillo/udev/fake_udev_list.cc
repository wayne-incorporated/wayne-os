// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <brillo/udev/fake_udev_list.h>

#include <optional>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>

namespace brillo {

NameValuePair::NameValuePair(std::string name, std::optional<std::string> value)
    : name_(std::move(name)), value_(std::move(value)) {}

NameValuePair::~NameValuePair() = default;

const char* NameValuePair::GetName() const {
  return name_.c_str();
}

const char* NameValuePair::GetValue() const {
  if (!value_.has_value())
    return nullptr;

  return value_.value().c_str();
}

FakeUdevList::FakeUdevList(std::vector<NameValuePair> entries)
    : entries_(std::move(entries)) {
  // Name can't be null, but value can be.
  for (const auto& entry : entries_)
    CHECK(entry.GetName());
}

FakeUdevList::~FakeUdevList() = default;

std::unique_ptr<UdevListEntry> FakeUdevList::GetFirstEntry() const {
  return entries_.empty() ? nullptr : std::make_unique<Entry>(this, 0);
}

FakeUdevList::Entry::Entry(const FakeUdevList* list, int index)
    : list_(list), index_(index) {
  CHECK_LT(index, list->entries_.size());
}

FakeUdevList::Entry::~Entry() = default;

std::unique_ptr<UdevListEntry> FakeUdevList::Entry::GetNext() const {
  if (index_ + 1 >= list_->entries_.size())
    return nullptr;
  return std::make_unique<Entry>(list_, index_ + 1);
}

std::unique_ptr<UdevListEntry> FakeUdevList::Entry::GetByName(
    const char* name) const {
  for (int i = index_; i < list_->entries_.size(); i++) {
    if (!strcmp(list_->entries_[i].GetName(), name))
      return std::make_unique<Entry>(list_, i);
  }
  return nullptr;
}

const char* FakeUdevList::Entry::GetName() const {
  return list_->entries_[index_].GetName();
}

const char* FakeUdevList::Entry::GetValue() const {
  return list_->entries_[index_].GetValue();
}

}  // namespace brillo
