/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/vendor_tag_manager.h"

#include <vector>

#include <base/check_op.h>
#include <base/strings/string_util.h>

#include "cros-camera/common.h"

namespace cros {

VendorTagManager::VendorTagManager() {
  vendor_tag_ops_t::get_tag_count = VendorTagManager::get_tag_count;
  vendor_tag_ops_t::get_all_tags = VendorTagManager::get_all_tags;
  vendor_tag_ops_t::get_section_name = VendorTagManager::get_section_name;
  vendor_tag_ops_t::get_tag_name = VendorTagManager::get_tag_name;
  vendor_tag_ops_t::get_tag_type = VendorTagManager::get_tag_type;
}

int VendorTagManager::GetTagCount() const {
  return tags_.size();
}

void VendorTagManager::GetAllTags(uint32_t* tag_array) const {
  if (tags_.empty()) {
    // No-op and tag_array might be null in this case.
    return;
  }
  DCHECK_NE(tag_array, nullptr);
  uint32_t* ptr = tag_array;
  for (const auto& tag : tags_) {
    *ptr++ = tag.first;
  }
}

const char* VendorTagManager::GetSectionName(uint32_t tag) const {
  auto it = tags_.find(tag);
  if (it == tags_.end()) {
    return nullptr;
  }
  return it->second.section_name.c_str();
}

const char* VendorTagManager::GetTagName(uint32_t tag) const {
  auto it = tags_.find(tag);
  if (it == tags_.end()) {
    return nullptr;
  }
  return it->second.tag_name.c_str();
}

int VendorTagManager::GetTagType(uint32_t tag) const {
  auto it = tags_.find(tag);
  if (it == tags_.end()) {
    return -1;
  }
  return it->second.type;
}

bool VendorTagManager::Add(vendor_tag_ops_t* ops) {
  DCHECK_NE(ops, nullptr);
  DCHECK_NE(ops->get_tag_count, nullptr);
  int n = ops->get_tag_count(ops);
  // get_tag_count may return error: negative int (camera_vendor_tags.h).
  if (n < 0) {
    return false;
  }
  std::vector<uint32_t> all_tags(n);
  ops->get_all_tags(ops, all_tags.data());
  for (uint32_t tag : all_tags) {
    const char* section_name = ops->get_section_name(ops, tag);
    const char* tag_name = ops->get_tag_name(ops, tag);
    int type = ops->get_tag_type(ops, tag);
    if (!Add(tag, section_name, tag_name, type)) {
      return false;
    }
  }
  return true;
}

bool VendorTagManager::Add(uint32_t tag,
                           const std::string& section_name,
                           const std::string& tag_name,
                           int type) {
  if (tag < CAMERA_METADATA_VENDOR_TAG_BOUNDARY ||
      tag >= kNextAvailableVendorTag) {
    LOGF(ERROR) << "Out-of-range tag " << std::showbase << std::hex << tag;
    return false;
  }

  std::string full_name = base::JoinString({section_name, tag_name}, ".");
  if (!full_names_.insert(full_name).second) {
    LOGF(ERROR) << "Duplicated tag name " << full_name;
    return false;
  }

  TagInfo info = {section_name, tag_name, type};
  if (!tags_.emplace(tag, info).second) {
    LOGF(ERROR) << "Duplicated tag " << std::showbase << std::hex << tag;
    return false;
  }

  return true;
}

// static
int VendorTagManager::get_tag_count(const vendor_tag_ops_t* v) {
  auto* self = static_cast<const VendorTagManager*>(v);
  return self->GetTagCount();
}

// static
void VendorTagManager::get_all_tags(const vendor_tag_ops_t* v,
                                    uint32_t* tag_array) {
  auto* self = static_cast<const VendorTagManager*>(v);
  return self->GetAllTags(tag_array);
}

// static
const char* VendorTagManager::get_section_name(const vendor_tag_ops_t* v,
                                               uint32_t tag) {
  auto* self = static_cast<const VendorTagManager*>(v);
  return self->GetSectionName(tag);
}

// static
const char* VendorTagManager::get_tag_name(const vendor_tag_ops_t* v,
                                           uint32_t tag) {
  auto* self = static_cast<const VendorTagManager*>(v);
  return self->GetTagName(tag);
}

// static
int VendorTagManager::get_tag_type(const vendor_tag_ops_t* v, uint32_t tag) {
  auto* self = static_cast<const VendorTagManager*>(v);
  return self->GetTagType(tag);
}

}  // namespace cros
