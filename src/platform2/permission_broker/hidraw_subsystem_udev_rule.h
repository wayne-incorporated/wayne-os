// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_HIDRAW_SUBSYSTEM_UDEV_RULE_H_
#define PERMISSION_BROKER_HIDRAW_SUBSYSTEM_UDEV_RULE_H_

#include <string>
#include <vector>

#include "permission_broker/hid_basictypes.h"
#include "permission_broker/rule.h"

namespace permission_broker {

// HidrawSubsystemUdevRule is a Rule that calls ProcessHidrawDevice on every
// device that belongs to the hidraw subsystem. All non-hidraw devices are
// ignored by this rule.
class HidrawSubsystemUdevRule : public Rule {
 public:
  explicit HidrawSubsystemUdevRule(const std::string& name);
  HidrawSubsystemUdevRule(const HidrawSubsystemUdevRule&) = delete;
  HidrawSubsystemUdevRule& operator=(const HidrawSubsystemUdevRule&) = delete;

  ~HidrawSubsystemUdevRule() override = default;

  // Called with every device belonging to the hidraw subsystem.
  virtual Result ProcessHidrawDevice(struct udev_device* device) = 0;

  Result ProcessDevice(struct udev_device* device) override;

  // This parses toplevel items from a report descriptor and extracts the usage
  // parameters of any toplevel collections.
  static bool ParseToplevelCollectionUsages(
      const HidReportDescriptor& descriptor, std::vector<HidUsage>* usages);

  // Populates a vector of HidUsage items using information parsed from a given
  // device's descriptor. Returns true iff the descriptor was processed without
  // errors.
  static bool GetHidToplevelUsages(struct udev_device* device,
                                   std::vector<HidUsage>* usages);
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_HIDRAW_SUBSYSTEM_UDEV_RULE_H_
