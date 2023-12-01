// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/udev_device.h"

#include <utility>

#include <base/logging.h>
#include <brillo/udev/mock_udev_device.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>
#include <brillo/udev/udev_monitor.h>
#include <gtest/gtest.h>
#include <linux/limits.h>
#include <rootdev/rootdev.h>

namespace cros_disks {
namespace {

using ::testing::Return;
using ::testing::StrictMock;

const char kLoopDevicePrefix[] = "/dev/loop";
const char kRamDeviceFile[] = "/dev/ram0";
const char kZRamDeviceFile[] = "/dev/zram0";

}  // namespace

class UdevDeviceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    udev_ = brillo::Udev::Create();
    if (!udev_)
      return;

    std::string boot_device_path = GetBootDevicePath();

    auto enumerate = udev_->CreateEnumerate();
    enumerate->AddMatchSubsystem("block");
    ASSERT_TRUE(enumerate->ScanDevices());

    for (auto entry = enumerate->GetListEntry(); entry;
         entry = entry->GetNext()) {
      const char* path = entry->GetName();
      auto device = udev_->CreateDeviceFromSysPath(path);
      if (!device)
        continue;

      const char* device_file = device->GetDeviceNode();
      if (!device_file)
        continue;

      if (!boot_device_ && !boot_device_path.empty() &&
          boot_device_path == device_file) {
        boot_device_ = udev_->CreateDeviceFromSysPath(path);

        // Check if the boot device is also mounted. If so, use it for tests
        // that expect a mounted device since the boot device is unlikely to
        // be unmounted during the tests.
        std::vector<std::string> mount_paths =
            UdevDevice::GetMountPaths(device_file);
        if (!mounted_device_ && !mount_paths.empty()) {
          mounted_device_ = udev_->CreateDeviceFromSysPath(path);
        }
      }

      if (!loop_device_ && device_file != boot_device_path &&
          strncmp(device_file, kLoopDevicePrefix, strlen(kLoopDevicePrefix)) ==
              0) {
        loop_device_ = udev_->CreateDeviceFromSysPath(path);
      }

      if (!ram_device_ && (strcmp(device_file, kRamDeviceFile) == 0 ||
                           strcmp(device_file, kZRamDeviceFile) == 0)) {
        ram_device_ = udev_->CreateDeviceFromSysPath(path);
      }

      if (!partitioned_device_) {
        const char* device_type = device->GetDeviceType();
        if (device_type && strcmp(device_type, "partition") == 0) {
          partitioned_device_ = device->GetParent();
        }
      }
    }
  }

  static std::string GetBootDevicePath() {
    char boot_device_path[PATH_MAX];
    if (rootdev(boot_device_path, sizeof(boot_device_path), true, true) == 0)
      return boot_device_path;
    return std::string();
  }

  std::unique_ptr<brillo::Udev> udev_;
  std::unique_ptr<brillo::UdevDevice> boot_device_;
  std::unique_ptr<brillo::UdevDevice> loop_device_;
  std::unique_ptr<brillo::UdevDevice> ram_device_;
  std::unique_ptr<brillo::UdevDevice> mounted_device_;
  std::unique_ptr<brillo::UdevDevice> partitioned_device_;
};

TEST_F(UdevDeviceTest, EnsureUTF8String) {
  // Valid UTF8
  EXPECT_EQ("ascii", UdevDevice::EnsureUTF8String("ascii"));
  EXPECT_EQ("\xc2\x81", UdevDevice::EnsureUTF8String("\xc2\x81"));
  // Invalid UTF8: overlong sequences
  EXPECT_EQ("", UdevDevice::EnsureUTF8String("\xc0\x80"));  // U+0000
}

TEST_F(UdevDeviceTest, IsValueBooleanTrue) {
  EXPECT_FALSE(UdevDevice::IsValueBooleanTrue(nullptr));
  EXPECT_FALSE(UdevDevice::IsValueBooleanTrue(""));
  EXPECT_FALSE(UdevDevice::IsValueBooleanTrue("0"));
  EXPECT_FALSE(UdevDevice::IsValueBooleanTrue("test"));
  EXPECT_TRUE(UdevDevice::IsValueBooleanTrue("1"));
}

TEST_F(UdevDeviceTest, IsAttributeTrueForNonexistentAttribute) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue("nonexistent-attribute"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_FALSE(device.IsAttributeTrue("nonexistent-attribute"));
}

TEST_F(UdevDeviceTest, HasAttributeForExistentAttribute) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_TRUE(device.HasAttribute("stat"));
    EXPECT_TRUE(device.HasAttribute("size"));
  }
}

TEST_F(UdevDeviceTest, GetAttributeForExistentAttribute) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_NE("", device.GetAttribute("size"));
  }
}

TEST_F(UdevDeviceTest, GetAttributeForNonexistentAttribute) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue("nonexistent-attribute"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_EQ("", device.GetAttribute("nonexistent-attribute"));
}

TEST_F(UdevDeviceTest, HasAttributeForNonexistentAttribute) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetSysAttributeValue("nonexistent-attribute"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_FALSE(device.HasAttribute("nonexistent-attribute"));
}

TEST_F(UdevDeviceTest, IsPropertyTrueForNonexistentProperty) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetPropertyValue("nonexistent-property"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_FALSE(device.IsPropertyTrue("nonexistent-property"));
}

TEST_F(UdevDeviceTest, GetPropertyForExistentProperty) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_NE("", device.GetProperty("DEVTYPE"));
  }
}

TEST_F(UdevDeviceTest, GetPropertyForNonexistentProperty) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetPropertyValue("nonexistent-property"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_EQ("", device.GetProperty("nonexistent-property"));
}

TEST_F(UdevDeviceTest, HasPropertyForExistentProperty) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_TRUE(device.HasProperty("DEVTYPE"));
    EXPECT_TRUE(device.HasProperty("DEVNAME"));
  }
}

TEST_F(UdevDeviceTest, HasPropertyForNonexistentProperty) {
  auto dev = std::make_unique<StrictMock<brillo::MockUdevDevice>>();
  EXPECT_CALL(*dev, GetPropertyValue("nonexistent-property"))
      .WillOnce(Return(nullptr));
  UdevDevice device(std::move(dev));
  EXPECT_FALSE(device.HasProperty("nonexistent-property"));
}

TEST_F(UdevDeviceTest, GetPropertyFromBlkIdForNonexistentProperty) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_EQ("", device.GetPropertyFromBlkId("nonexistent-property"));
  }
}

TEST_F(UdevDeviceTest, GetPartitionCount) {
  if (partitioned_device_) {
    UdevDevice device(std::move(partitioned_device_));
    EXPECT_NE(0, device.GetPartitionCount());
  }
}

TEST_F(UdevDeviceTest, IsAutoMountable) {
  if (boot_device_) {
    UdevDevice device(std::move(boot_device_));
    EXPECT_FALSE(device.IsAutoMountable());
  }
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_FALSE(device.IsAutoMountable());
  }
}

TEST_F(UdevDeviceTest, IsIgnored) {
  if (boot_device_) {
    UdevDevice device(std::move(boot_device_));
    EXPECT_FALSE(device.IsIgnored());
  }
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_FALSE(device.IsIgnored());
  }
  if (ram_device_) {
    UdevDevice device(std::move(ram_device_));
    EXPECT_TRUE(device.IsIgnored());
  }
}

TEST_F(UdevDeviceTest, IsOnBootDevice) {
  if (boot_device_) {
    UdevDevice device(std::move(boot_device_));
    EXPECT_TRUE(device.IsOnBootDevice());
  }
#if 0
  // TODO(benchan): Re-enable this test case after figuring out why it fails on
  // some buildbot (chromium:866231).
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_FALSE(device.IsOnBootDevice());
  }
#endif
}

TEST_F(UdevDeviceTest, IsOnRemovableDevice) {
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_FALSE(device.IsOnRemovableDevice());
  }
}

TEST_F(UdevDeviceTest, IsMediaAvailable) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    EXPECT_TRUE(device.IsMediaAvailable());
  }
}

TEST_F(UdevDeviceTest, IsMobileBroadbandDevice) {
  if (boot_device_) {
    UdevDevice device(std::move(boot_device_));
    EXPECT_FALSE(device.IsMobileBroadbandDevice());
  }
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_FALSE(device.IsMobileBroadbandDevice());
  }
}

TEST_F(UdevDeviceTest, IsVirtual) {
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_TRUE(device.IsVirtual());
  }
  if (ram_device_) {
    UdevDevice device(std::move(ram_device_));
    EXPECT_TRUE(device.IsVirtual());
  }
}

TEST_F(UdevDeviceTest, IsLoopDevice) {
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    EXPECT_TRUE(device.IsLoopDevice());
  }
  if (ram_device_) {
    UdevDevice device(std::move(ram_device_));
    EXPECT_FALSE(device.IsLoopDevice());
  }
}

TEST_F(UdevDeviceTest, GetSizeInfo) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    uint64_t total_size = 0, remaining_size = 0;
    device.GetSizeInfo(&total_size, &remaining_size);
    LOG(INFO) << "GetSizeInfo: total=" << total_size
              << ", remaining=" << remaining_size;
    EXPECT_GT(total_size, 0);
  }
}

TEST_F(UdevDeviceTest, GetMountPaths) {
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    std::vector<std::string> mount_paths = device.GetMountPaths();
    EXPECT_FALSE(mount_paths.empty());
  }
}

TEST_F(UdevDeviceTest, ToDisk) {
  if (boot_device_) {
    UdevDevice device(std::move(boot_device_));
    Disk disk = device.ToDisk();
    EXPECT_FALSE(disk.is_auto_mountable);
    EXPECT_TRUE(disk.is_on_boot_device);
  }
  if (loop_device_) {
    UdevDevice device(std::move(loop_device_));
    Disk disk = device.ToDisk();
    EXPECT_FALSE(disk.is_auto_mountable);
    EXPECT_TRUE(disk.is_virtual);
    EXPECT_EQ(kLoopDevicePrefix,
              disk.device_file.substr(0, strlen(kLoopDevicePrefix)));
  }
  if (mounted_device_) {
    UdevDevice device(std::move(mounted_device_));
    Disk disk = device.ToDisk();
    EXPECT_TRUE(disk.IsMounted());
    EXPECT_FALSE(disk.mount_paths.empty());
  }
}

}  // namespace cros_disks
