// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_TEST_GUEST_METRICS_H_
#define VM_TOOLS_CICERONE_TEST_GUEST_METRICS_H_

#include <string>

#include "vm_tools/cicerone/guest_metrics.h"

namespace vm_tools {
namespace cicerone {

class TestGuestMetrics : public GuestMetrics {
 public:
  explicit TestGuestMetrics(scoped_refptr<dbus::Bus> bus,
                            base::FilePath cumulative_metrics_path,
                            const std::string& owner_id,
                            const std::string& vm_name,
                            const std::string& container_name)
      : GuestMetrics(bus, cumulative_metrics_path),
        owner_id_(owner_id),
        vm_name_(vm_name),
        container_name_(container_name) {}
  TestGuestMetrics(const TestGuestMetrics&) = delete;
  TestGuestMetrics& operator=(const TestGuestMetrics&) = delete;
  ~TestGuestMetrics() override = default;

  bool HandleMetric(const std::string& owner_id,
                    const std::string& vm_name,
                    const std::string& container_name,
                    const std::string& name,
                    int value) override {
    // Replace vm_name and container_name, which will be the default values from
    // ServiceTestingHelper::kDefaultOwnerId, kDefaultVmName and
    // kDefaultContainerName, with the values provided by the current test.
    return GuestMetrics::HandleMetric(owner_id_, vm_name_, container_name_,
                                      name, value);
  }

 private:
  std::string owner_id_;
  std::string vm_name_;
  std::string container_name_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_TEST_GUEST_METRICS_H_
