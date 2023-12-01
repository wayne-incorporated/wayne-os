/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_VENDOR_TAG_MANAGER_H_
#define CAMERA_COMMON_VENDOR_TAG_MANAGER_H_

#include <cstdint>
#include <map>
#include <set>
#include <string>

#include "cros-camera/export.h"
#include "system/camera_vendor_tags.h"

namespace cros {

// These are half-closed intervals as [kFooStart, kFooEnd).
const uint32_t kPortraitModeVendorTagStart = 0x80000000;
const uint32_t kPortraitModeVendorTagEnd = 0x80010000;

const uint32_t kUsbHalVendorTagStart = 0x80010000;
const uint32_t kUsbHalVendorTagEnd = 0x80020000;

const uint32_t kCamxHalVendorTagStart = 0x80020000;
const uint32_t kCamxHalVendorTagEnd = 0x80030000;

const uint32_t kArcvmVendorTagStart = 0x80030000;
const uint32_t kArcvmVendorTagEnd = 0x80040000;

const uint32_t kIntelIpu6VendorTagStart = 0x80040000;
const uint32_t kintelIpu6VendorTagEnd = 0x80050000;

const uint32_t kCrosZslVendorTagStart = 0x80050000;
const uint32_t kCrosZslVendorTagEnd = 0x80060000;

const uint32_t kCrosRotateAndCropVendorTagStart = 0x80060000;
const uint32_t kCrosRotateAndCropVendorTagEnd = 0x80070000;

// Please update this value when allocating a new interval, such as
// const uint32_t kFooVendorTagStart = {value of kNextAvailableVendorTag};
// const uint32_t kFooVendorTagEnd = ...;
// const uint32_t kNextAvailableVendorTag = {value of kFooVendorTagEnd};
const uint32_t kNextAvailableVendorTag = kCrosRotateAndCropVendorTagEnd;

class CROS_CAMERA_EXPORT VendorTagManager : public vendor_tag_ops_t {
 public:
  VendorTagManager();
  VendorTagManager(const VendorTagManager&) = default;
  VendorTagManager& operator=(const VendorTagManager&) = default;
  ~VendorTagManager() = default;

  // The functions for querying the tags and implementing |vendor_tag_ops_t|.
  int GetTagCount() const;
  void GetAllTags(uint32_t* tag_array) const;
  const char* GetSectionName(uint32_t tag) const;
  const char* GetTagName(uint32_t tag) const;
  int GetTagType(uint32_t tag) const;

  // The static version of vendor_tag_ops_t implementations.
  static int get_tag_count(const vendor_tag_ops_t* v);
  static void get_all_tags(const vendor_tag_ops_t* v, uint32_t* tag_array);
  static const char* get_section_name(const vendor_tag_ops_t* v, uint32_t tag);
  static const char* get_tag_name(const vendor_tag_ops_t* v, uint32_t tag);
  static int get_tag_type(const vendor_tag_ops_t* v, uint32_t tag);

  // Adds all tags defined in |ops|. Returns true on success.
  bool Add(vendor_tag_ops_t* ops);

  // Adds a tag. Returns true on success.
  bool Add(uint32_t tag,
           const std::string& section_name,
           const std::string& tag_name,
           int type);

 private:
  struct TagInfo {
    std::string section_name;
    std::string tag_name;
    int type;
  };

  std::map<uint32_t, TagInfo> tags_;
  std::set<std::string> full_names_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_VENDOR_TAG_MANAGER_H_
