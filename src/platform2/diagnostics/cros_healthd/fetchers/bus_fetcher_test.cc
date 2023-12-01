// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <brillo/variant_dictionary.h>
#include <fwupd/dbus-proxy-mocks.h>
#include <libfwupd/fwupd-enums.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher_constants.h"
#include "diagnostics/cros_healthd/system/mock_context.h"
#include "diagnostics/cros_healthd/utils/fwupd_utils.h"
#include "diagnostics/cros_healthd/utils/mojo_type_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils_constants.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;

using ::testing::_;
using ::testing::Invoke;
using ::testing::WithArg;

class FakeUdevDevice : public brillo::MockUdevDevice {
 public:
  FakeUdevDevice(const std::string& vendor_name, const std::string& device_name)
      : vendor_name_(vendor_name), device_name_(device_name) {
    EXPECT_CALL(*this, GetPropertyValue)
        .WillRepeatedly(Invoke([this](const char* key) {
          if (std::string(key) == kPropertieVendorFromDB)
            return vendor_name_.c_str();
          if (std::string(key) == kPropertieModelFromDB)
            return device_name_.c_str();
          return "";
        }));
  }
  ~FakeUdevDevice() = default;

 private:
  std::string vendor_name_;
  std::string device_name_;
};

class BusFetcherTest : public BaseFileTest {
 public:
  BusFetcherTest() = default;
  BusFetcherTest(const BusFetcherTest&) = delete;
  BusFetcherTest& operator=(const BusFetcherTest&) = delete;

  void SetUp() override {
    SetTestRoot(mock_context_.root_dir());
    MockUdevDevice("", "");
    MockFwupdProxy({});
  }

  void MockUdevDevice(const std::string& vendor_name,
                      const std::string& device_name) {
    EXPECT_CALL(*mock_context_.mock_udev(), CreateDeviceFromSysPath)
        .WillRepeatedly(Invoke([=](const char* syspath) {
          auto udevice =
              std::make_unique<FakeUdevDevice>(vendor_name, device_name);
          return udevice;
        }));
  }

  void MockFwupdProxy(
      const std::vector<brillo::VariantDictionary>& fwupd_response) {
    EXPECT_CALL(*mock_context_.mock_fwupd_proxy(), GetDevicesAsync)
        .WillRepeatedly(WithArg<0>(
            Invoke([=](base::OnceCallback<void(
                           const std::vector<brillo::VariantDictionary>&)>
                           success_callback) {
              std::move(success_callback).Run(std::move(fwupd_response));
            })));
  }

  // Creates a pci device with default attributes. Returns the device's
  // directory so tests can modify the attributes.
  base::FilePath SetDefaultPciDevice(size_t id) {
    const auto dir = "/sys/devices/pci0000:00";
    const auto dev = base::StringPrintf("0000:00:%02zx.0", id);
    SetSymbolicLink({"../../../devices/pci0000:00", dev}, {kPathSysPci, dev});

    SetFile({dir, dev, kFilePciClass}, "0x0a1b2c");
    SetFile({dir, dev, kFilePciVendor}, "0x12ab");
    SetFile({dir, dev, kFilePciDevice}, "0x34cd");
    return base::FilePath{dir}.Append(dev);
  }

  // Creates a usb device with default attributes. Returns the device's
  // directory so tests can modify the attributes.
  base::FilePath SetDefaultUsbDevice(size_t id) {
    const auto dir = "/sys/devices/pci0000:00/0000:00:14.0/usb1";
    const auto dev = base::StringPrintf("1-%zu", id);
    SetSymbolicLink({"../../../devices/pci0000:00/0000:00:14.0/usb1", dev},
                    {kPathSysUsb, dev});

    SetFile({dir, dev, kFileUsbDevClass}, "00");
    SetFile({dir, dev, kFileUsbDevSubclass}, "00");
    SetFile({dir, dev, kFileUsbDevProtocol}, "00");
    SetFile({dir, dev, kFileUsbVendor}, "0000");
    SetFile({dir, dev, kFileUsbProduct}, "0000");
    SetFile({dir, dev, kFileUsbSpeed}, "5000");

    const auto dev_path = base::FilePath{dir}.Append(dev);
    SetDefaultUsbInterface(dev_path, id, 0);
    return dev_path;
  }

  // Creates a usb interface with default attributes. Returns the interface's
  // directory so tests can modify the attributes.
  base::FilePath SetDefaultUsbInterface(const base::FilePath& dev,
                                        size_t device_id,
                                        size_t interface_id) {
    const auto dev_if =
        dev.Append(base::StringPrintf("1-%zu:1.%zu", device_id, interface_id));
    SetFile(dev_if.Append(kFileUsbIFNumber),
            base::StringPrintf("%02zx", interface_id));
    SetFile(dev_if.Append(kFileUsbIFClass), "00");
    SetFile(dev_if.Append(kFileUsbIFSubclass), "00");
    SetFile(dev_if.Append(kFileUsbIFProtocol), "00");
    return dev_if;
  }

  // Creates a thunderbolt device with default attributes. Returns the
  // device's directory so tests can modify the attributes.
  base::FilePath SetDefaultThunderboltDevice(size_t id) {
    const auto dir = "/sys/devices/pci0000:00/0000:00:14.0";
    const auto dev = base::StringPrintf("domain%zu/", id);
    SetSymbolicLink({"../../../devices/pci0000:00/0000:00:14.0", dev},
                    {kPathSysThunderbolt, dev});

    SetFile({dir, dev, kFileThunderboltSecurity}, "none");

    const auto dev_path = base::FilePath{dir}.Append(dev);
    SetDefaultThunderboltInterface(dev_path, id, 0);
    return dev_path;
  }

  // Creates a thunderbolt interface with default attributes. Returns the
  // interface's directory so tests can modify the attributes.
  base::FilePath SetDefaultThunderboltInterface(const base::FilePath& dev,
                                                size_t device_id,
                                                size_t interface_id) {
    const auto dev_if = base::StringPrintf("%zu-%zu:%zu.%zu", device_id,
                                           device_id, device_id, interface_id);
    base::FilePath link_target{"../../../"};
    EXPECT_TRUE(base::FilePath{"/sys"}.AppendRelativePath(dev, &link_target));
    SetSymbolicLink(link_target.Append(dev_if), {kPathSysThunderbolt, dev_if});

    const auto dev_str = dev.value();
    SetFile({dev_str, dev_if, kFileThunderboltAuthorized}, "0");
    SetFile({dev_str, dev_if, kFileThunderboltRxSpeed}, "20.0 Gb/s");
    SetFile({dev_str, dev_if, kFileThunderboltTxSpeed}, "20.0 Gb/s");
    SetFile({dev_str, dev_if, kFileThunderboltVendorName}, "");
    SetFile({dev_str, dev_if, kFileThunderboltDeviceName}, "");
    SetFile({dev_str, dev_if, kFileThunderboltDeviceType}, "");
    SetFile({dev_str, dev_if, kFileThunderboltUUID}, "");
    SetFile({dev_str, dev_if, kFileThunderboltFWVer}, "");
    return dev.Append(dev_if);
  }

  std::vector<mojom::BusDevicePtr> FetchBusDevicesSync() {
    base::test::TestFuture<mojom::BusResultPtr> future;
    FetchBusDevices(&mock_context_, future.GetCallback());
    EXPECT_TRUE(future.Get()->is_bus_devices());
    return std::move(future.Take()->get_bus_devices());
  }

  base::flat_map<base::FilePath, mojom::BusDevicePtr>
  FetchSysfsPathsBusDeviceMapSync() {
    base::test::TestFuture<base::flat_map<base::FilePath, mojom::BusDevicePtr>>
        future;
    FetchSysfsPathsBusDeviceMap(&mock_context_, future.GetCallback());
    return future.Take();
  }

 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  MockContext mock_context_;
};

TEST_F(BusFetcherTest, TestFetchPciBasic) {
  const auto dev = SetDefaultPciDevice(0);
  SetFile(dev.Append(kFilePciClass), "0x0a1b2c");
  SetFile(dev.Append(kFilePciVendor), "0x12ab");
  SetFile(dev.Append(kFilePciDevice), "0x34cd");
  SetFile(dev.Append(kFilePciSubVendor), "0x1234");
  SetFile(dev.Append(kFilePciSubDevice), "0x5678");
  SetSymbolicLink({"../../../bus/pci/drivers", "my_driver"},
                  dev.Append(kFileDriver));

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->bus_info->which(), mojom::BusInfo::Tag::kPciBusInfo);
  // Sets by FakePciUtil.
  EXPECT_EQ(res[0]->vendor_name, "Vendor:12AB");
  EXPECT_EQ(res[0]->product_name, "Device:34CD");

  const auto& pci_info = res[0]->bus_info->get_pci_bus_info();
  EXPECT_EQ(pci_info->class_id, 0x0a);
  EXPECT_EQ(pci_info->subclass_id, 0x1b);
  EXPECT_EQ(pci_info->prog_if_id, 0x2c);
  EXPECT_EQ(pci_info->vendor_id, 0x12ab);
  EXPECT_EQ(pci_info->device_id, 0x34cd);
  EXPECT_EQ(pci_info->sub_vendor_id, mojom::NullableUint16::New(0x1234));
  EXPECT_EQ(pci_info->sub_device_id, mojom::NullableUint16::New(0x5678));
  EXPECT_EQ(pci_info->driver, "my_driver");
}

TEST_F(BusFetcherTest, TestFetchPciNullableFields) {
  SetDefaultPciDevice(0);

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->bus_info->which(), mojom::BusInfo::Tag::kPciBusInfo);
  const auto& pci_info = res[0]->bus_info->get_pci_bus_info();
  EXPECT_FALSE(pci_info->sub_vendor_id);
  EXPECT_FALSE(pci_info->sub_device_id);
  EXPECT_EQ(pci_info->driver, std::nullopt);
}

TEST_F(BusFetcherTest, TestFetchPciSubInfoZero) {
  const auto dev = SetDefaultPciDevice(0);
  SetFile(dev.Append(kFilePciSubVendor), "0x0000");
  SetFile(dev.Append(kFilePciSubDevice), "0x0000");

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->bus_info->which(), mojom::BusInfo::Tag::kPciBusInfo);
  const auto& pci_info = res[0]->bus_info->get_pci_bus_info();
  // Zero should be parsed as null.
  EXPECT_FALSE(pci_info->sub_vendor_id);
  EXPECT_FALSE(pci_info->sub_device_id);
}

TEST_F(BusFetcherTest, TestFetchUsbBasic) {
  size_t dev_id = 0;
  const auto dev = SetDefaultUsbDevice(dev_id);
  const auto dev_if = SetDefaultUsbInterface(dev, dev_id, 0);

  // Assume that the parent directory is the root hub.
  const auto usb_root = dev.DirName();
  // Set usb version to make it a valid usb root hub.
  SetFile(usb_root.Append(kFileUsbVendor), kLinuxFoundationVendorId);
  SetFile(usb_root.Append(kFileUsbProduct),
          /*LinuxFoundationUsb1ProductId*/ "1");

  SetFile(dev.Append(kFileUsbDevClass), "0a");
  SetFile(dev.Append(kFileUsbDevSubclass), "1b");
  SetFile(dev.Append(kFileUsbDevProtocol), "2c");
  SetFile(dev.Append(kFileUsbVendor), "12ab");
  SetFile(dev.Append(kFileUsbProduct), "34cd");
  SetFile(dev.Append(kFileUsbSpeed), "5000");
  MockUdevDevice("FakeVendor", "FakeDevice");
  MockFwupdProxy({{
      {fwupd_utils::kFwupdResultKeyVendorId, std::string{"USB:0x12AB"}},
      {fwupd_utils::kFwupdResultKeyInstanceIds,
       std::vector<std::string>{"USB\\VID_12AB&PID_34CDX"}},
      {fwupd_utils::kFwupdResultKeyVersion, std::string{"FakeFirmwareVersion"}},
      {fwupd_utils::kFwupdResultKeyVersionFormat,
       static_cast<uint32_t>(FWUPD_VERSION_FORMAT_PLAIN)},
  }});
  SetFile(dev_if.Append(kFileUsbIFClass), "0a");
  SetFile(dev_if.Append(kFileUsbIFSubclass), "1b");
  SetFile(dev_if.Append(kFileUsbIFProtocol), "2c");
  SetSymbolicLink({"../../../../../../bus/usb/drivers", "my_driver"},
                  dev_if.Append(kFileDriver));

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->bus_info->which(), mojom::BusInfo::Tag::kUsbBusInfo);
  EXPECT_EQ(res[0]->vendor_name, "FakeVendor");
  EXPECT_EQ(res[0]->product_name, "FakeDevice");

  const auto& usb_info = res[0]->bus_info->get_usb_bus_info();
  EXPECT_EQ(usb_info->class_id, 0x0a);
  EXPECT_EQ(usb_info->subclass_id, 0x1b);
  EXPECT_EQ(usb_info->protocol_id, 0x2c);
  EXPECT_EQ(usb_info->vendor_id, 0x12ab);
  EXPECT_EQ(usb_info->product_id, 0x34cd);
  EXPECT_EQ(usb_info->spec_speed, mojom::UsbSpecSpeed::k5Gbps);
  EXPECT_EQ(usb_info->version, mojom::UsbVersion::kUsb1);
  EXPECT_EQ(usb_info->fwupd_firmware_version_info->version,
            "FakeFirmwareVersion");
  EXPECT_EQ(usb_info->fwupd_firmware_version_info->version_format,
            mojom::FwupdVersionFormat::kPlain);
  EXPECT_EQ(usb_info->interfaces.size(), 1);
  EXPECT_EQ(usb_info->interfaces[0]->interface_number, 0);
  EXPECT_EQ(usb_info->interfaces[0]->class_id, 0x0a);
  EXPECT_EQ(usb_info->interfaces[0]->subclass_id, 0x1b);
  EXPECT_EQ(usb_info->interfaces[0]->protocol_id, 0x2c);
  EXPECT_EQ(usb_info->interfaces[0]->driver, "my_driver");
}

TEST_F(BusFetcherTest, TestFetchUsbNullalbeFields) {
  SetDefaultUsbDevice(0);

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->bus_info->which(), mojom::BusInfo::Tag::kUsbBusInfo);
  const auto& usb_info = res[0]->bus_info->get_usb_bus_info();
  EXPECT_FALSE(usb_info->fwupd_firmware_version_info);
  EXPECT_EQ(usb_info->interfaces.size(), 1);
  EXPECT_EQ(usb_info->interfaces[0]->driver, std::nullopt);
}

TEST_F(BusFetcherTest, TestFetchThunderboltBusInfo) {
  size_t dev_id = 0;
  const auto dev = SetDefaultThunderboltDevice(dev_id);
  const auto dev_if = SetDefaultThunderboltInterface(dev, dev_id, 0);
  SetFile(dev.Append(kFileThunderboltSecurity), "secure");

  SetFile(dev_if.Append(kFileThunderboltAuthorized), "1");
  SetFile(dev_if.Append(kFileThunderboltRxSpeed), "40.0 Gb/s");
  SetFile(dev_if.Append(kFileThunderboltTxSpeed), "60.0 Gb/s");
  SetFile(dev_if.Append(kFileThunderboltVendorName), "ThunderboltVendorName");
  SetFile(dev_if.Append(kFileThunderboltDeviceName), "ThunderboltDeviceName");
  SetFile(dev_if.Append(kFileThunderboltDeviceType), "0x4257");
  SetFile(dev_if.Append(kFileThunderboltUUID),
          "d5010000-0060-6508-2304-61066ed3f91e");
  SetFile(dev_if.Append(kFileThunderboltFWVer), "29.0");

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 1);
  EXPECT_EQ(res[0]->vendor_name, "ThunderboltVendorName");
  EXPECT_EQ(res[0]->product_name, "ThunderboltDeviceName");
  EXPECT_EQ(res[0]->bus_info->which(),
            mojom::BusInfo::Tag::kThunderboltBusInfo);
  const auto& tdb_info = res[0]->bus_info->get_thunderbolt_bus_info();
  EXPECT_EQ(tdb_info->security_level,
            mojom::ThunderboltSecurityLevel::kSecureLevel);

  EXPECT_EQ(tdb_info->thunderbolt_interfaces.size(), 1);
  const auto& tbd_if = tdb_info->thunderbolt_interfaces[0];
  EXPECT_TRUE(tbd_if->authorized);
  EXPECT_EQ(tbd_if->rx_speed_gbs, 40);
  EXPECT_EQ(tbd_if->tx_speed_gbs, 60);
  EXPECT_EQ(tbd_if->vendor_name, "ThunderboltVendorName");
  EXPECT_EQ(tbd_if->device_name, "ThunderboltDeviceName");
  EXPECT_EQ(tbd_if->device_type, "0x4257");
  EXPECT_EQ(tbd_if->device_uuid, "d5010000-0060-6508-2304-61066ed3f91e");
  EXPECT_EQ(tbd_if->device_fw_version, "29.0");
}

TEST_F(BusFetcherTest, TestFetchMultiple) {
  SetDefaultPciDevice(0);
  SetDefaultPciDevice(1);
  SetDefaultPciDevice(42);

  SetDefaultUsbDevice(0);
  {
    const auto dev = SetDefaultUsbDevice(1);
    SetDefaultUsbInterface(dev, 1, 1);
  }
  {
    const auto dev = SetDefaultUsbDevice(42);
    SetDefaultUsbInterface(dev, 42, 1);
    SetDefaultUsbInterface(dev, 42, 2);
  }

  SetDefaultThunderboltDevice(0);
  {
    const auto dev = SetDefaultThunderboltDevice(1);
    SetDefaultThunderboltInterface(dev, 1, 1);
  }

  auto res = FetchBusDevicesSync();
  EXPECT_EQ(res.size(), 8);
  std::multiset<mojom::BusInfo::Tag> type_count;
  for (const auto& dev : res) {
    type_count.insert(dev->bus_info->which());
  }
  EXPECT_EQ(type_count.count(mojom::BusInfo::Tag::kPciBusInfo), 3);
  EXPECT_EQ(type_count.count(mojom::BusInfo::Tag::kUsbBusInfo), 3);
  EXPECT_EQ(type_count.count(mojom::BusInfo::Tag::kThunderboltBusInfo), 2);
}

TEST_F(BusFetcherTest, TestFetchSysfsPathsBusDeviceMapPci) {
  const auto dev = SetDefaultPciDevice(0);

  auto result = FetchSysfsPathsBusDeviceMapSync();
  EXPECT_EQ(result.begin()->first, GetPathUnderRoot(dev));
}

TEST_F(BusFetcherTest, TestFetchSysfsPathsBusDeviceMapUsb) {
  const auto dev = SetDefaultUsbDevice(0);

  auto result = FetchSysfsPathsBusDeviceMapSync();
  EXPECT_EQ(result.begin()->first, GetPathUnderRoot(dev));
}

TEST_F(BusFetcherTest, TestFetchSysfsPathsBusDeviceMapThunderbolt) {
  const auto dev = SetDefaultThunderboltDevice(0);

  auto result = FetchSysfsPathsBusDeviceMapSync();
  EXPECT_EQ(result.begin()->first, GetPathUnderRoot(dev));
}

}  // namespace
}  // namespace diagnostics
