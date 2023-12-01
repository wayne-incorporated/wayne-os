// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/device_tracker.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/run_loop.h>
#include <base/files/file.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>

#include "lorgnette/sane_client_fake.h"
#include "lorgnette/test_util.h"
#include "lorgnette/usb/libusb_wrapper_fake.h"
#include "lorgnette/usb/usb_device_fake.h"

using ::testing::_;
using ::testing::ElementsAre;

namespace lorgnette {

namespace {

TEST(DeviceTrackerTest, CreateMultipleSessions) {
  base::test::SingleThreadTaskEnvironment task_environment;
  base::RunLoop run_loop;

  std::vector<std::string> closed_sessions;
  auto signal_handler = base::BindLambdaForTesting(
      [&closed_sessions](const ScannerListChangedSignal& signal) {
        if (signal.event_type() == ScannerListChangedSignal::SESSION_ENDING) {
          closed_sessions.push_back(signal.session_id());
        }
      });

  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  auto tracker =
      std::make_unique<DeviceTracker>(sane_client.get(), libusb.get());
  tracker->SetScannerListChangedSignalSender(signal_handler);

  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);

  StartScannerDiscoveryRequest start_request;
  start_request.set_client_id("client_1");
  StartScannerDiscoveryResponse response1 =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_TRUE(response1.started());
  EXPECT_FALSE(response1.session_id().empty());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 1);

  start_request.set_client_id("client_2");
  StartScannerDiscoveryResponse response2 =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_TRUE(response2.started());
  EXPECT_FALSE(response2.session_id().empty());
  EXPECT_NE(response1.session_id(), response2.session_id());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 2);

  StopScannerDiscoveryRequest stop_request;
  stop_request.set_session_id(response1.session_id());
  StopScannerDiscoveryResponse stop1 =
      tracker->StopScannerDiscovery(stop_request);
  EXPECT_TRUE(stop1.stopped());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 1);

  stop_request.set_session_id(response2.session_id());
  StopScannerDiscoveryResponse stop2 =
      tracker->StopScannerDiscovery(stop_request);
  EXPECT_TRUE(stop2.stopped());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);

  EXPECT_THAT(closed_sessions,
              ElementsAre(response1.session_id(), response2.session_id()));
}

TEST(DeviceTrackerTest, CreateDuplicateSessions) {
  base::test::SingleThreadTaskEnvironment task_environment;
  base::RunLoop run_loop;

  std::vector<std::string> closed_sessions;
  auto signal_handler = base::BindLambdaForTesting(
      [&closed_sessions](const ScannerListChangedSignal& signal) {
        if (signal.event_type() == ScannerListChangedSignal::SESSION_ENDING) {
          closed_sessions.push_back(signal.session_id());
        }
      });

  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  auto tracker =
      std::make_unique<DeviceTracker>(sane_client.get(), libusb.get());
  tracker->SetScannerListChangedSignalSender(signal_handler);

  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);

  StartScannerDiscoveryRequest start_request;
  start_request.set_client_id("client_1");
  StartScannerDiscoveryResponse response1 =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_TRUE(response1.started());
  EXPECT_FALSE(response1.session_id().empty());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 1);

  start_request.set_client_id("client_1");
  StartScannerDiscoveryResponse response2 =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_TRUE(response2.started());
  EXPECT_FALSE(response2.session_id().empty());
  EXPECT_EQ(response1.session_id(), response2.session_id());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 1);

  StopScannerDiscoveryRequest stop_request;
  stop_request.set_session_id(response1.session_id());
  StopScannerDiscoveryResponse stop1 =
      tracker->StopScannerDiscovery(stop_request);
  EXPECT_TRUE(stop1.stopped());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);

  stop_request.set_session_id(response2.session_id());
  StopScannerDiscoveryResponse stop2 =
      tracker->StopScannerDiscovery(stop_request);
  EXPECT_TRUE(stop2.stopped());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);

  // Session ID should get closed twice even though it doesn't exist the second
  // time.
  EXPECT_THAT(closed_sessions,
              ElementsAre(response1.session_id(), response1.session_id()));
}

TEST(DeviceTrackerTest, StartSessionMissingClient) {
  base::test::SingleThreadTaskEnvironment task_environment;
  base::RunLoop run_loop;

  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  auto tracker =
      std::make_unique<DeviceTracker>(sane_client.get(), libusb.get());

  StartScannerDiscoveryRequest start_request;
  start_request.set_client_id("");
  StartScannerDiscoveryResponse response =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_FALSE(response.started());
  EXPECT_TRUE(response.session_id().empty());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);
}

TEST(DeviceTrackerTest, StopSessionMissingID) {
  base::test::SingleThreadTaskEnvironment task_environment;
  base::RunLoop run_loop;

  std::vector<std::string> closed_sessions;
  auto signal_handler = base::BindLambdaForTesting(
      [&closed_sessions](const ScannerListChangedSignal& signal) {
        if (signal.event_type() == ScannerListChangedSignal::SESSION_ENDING) {
          closed_sessions.push_back(signal.session_id());
        }
      });

  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  auto tracker =
      std::make_unique<DeviceTracker>(sane_client.get(), libusb.get());
  tracker->SetScannerListChangedSignalSender(signal_handler);

  StopScannerDiscoveryRequest stop_request;
  stop_request.set_session_id("");
  StopScannerDiscoveryResponse response =
      tracker->StopScannerDiscovery(stop_request);
  EXPECT_FALSE(response.stopped());
  EXPECT_TRUE(closed_sessions.empty());
  EXPECT_EQ(tracker->NumActiveDiscoverySessions(), 0);
}

// Test the whole flow with several fake USB devices.  Confirm that
// exactly and only the devices that fully match the checks and have a SANE
// backend have a signal emitted before shutting down the session.
TEST(DeviceTrackerTest, CompleteDiscoverySession) {
  // Scanner that supports eSCL over IPP-USB.
  auto ippusb_escl_device = std::make_unique<UsbDeviceFake>();

  libusb_device_descriptor device_desc = MakeMinimalDeviceDescriptor();
  device_desc.bDeviceClass = LIBUSB_CLASS_PER_INTERFACE;
  device_desc.bNumConfigurations = 1;
  device_desc.iManufacturer = 1;
  device_desc.iProduct = 2;
  ippusb_escl_device->SetStringDescriptors(
      {"", "GoogleTest", "eSCL Scanner 3000"});
  ippusb_escl_device->SetDeviceDescriptor(device_desc);

  // One altsetting with a printer class and the IPP-USB protocol.
  auto altsetting = MakeIppUsbInterfaceDescriptor();

  // One interface containing the altsetting.
  auto interface = std::make_unique<libusb_interface>();
  interface->num_altsetting = 1;
  interface->altsetting = altsetting.get();

  // One config descriptor containing the interface.
  libusb_config_descriptor descriptor;
  memset(&descriptor, 0, sizeof(descriptor));
  descriptor.bLength = sizeof(descriptor);
  descriptor.bDescriptorType = LIBUSB_DT_CONFIG;
  descriptor.wTotalLength = sizeof(descriptor);
  descriptor.bNumInterfaces = 1;
  descriptor.interface = interface.get();

  ippusb_escl_device->SetConfigDescriptors({descriptor});
  ippusb_escl_device->Init();

  // Printer that supports IPP-USB but not eSCL.
  auto ippusb_printer = UsbDeviceFake::Clone(*ippusb_escl_device.get());
  ippusb_printer->MutableDeviceDescriptor().idProduct = 0x6543;
  ippusb_printer->SetStringDescriptors(
      {"", "GoogleTest", "IPP-USB Printer 2000"});

  // Printer that doesn't support IPP-USB.
  auto printer_altsetting = MakeIppUsbInterfaceDescriptor();
  printer_altsetting->bInterfaceProtocol = 0;
  auto printer_interface = std::make_unique<libusb_interface>();
  printer_interface->num_altsetting = 1;
  printer_interface->altsetting = printer_altsetting.get();
  auto usb_printer = UsbDeviceFake::Clone(*ippusb_printer.get());
  usb_printer->MutableDeviceDescriptor().idProduct = 0x7654;
  usb_printer->MutableConfigDescriptor(0).interface = printer_interface.get();
  usb_printer->SetStringDescriptors({"", "GoogleTest", "USB Printer 1000"});

  // Not a printer at all.
  auto non_printer = UsbDeviceFake::Clone(*usb_printer.get());
  non_printer->MutableDeviceDescriptor().idProduct = 0x7654;
  non_printer->MutableDeviceDescriptor().bDeviceClass = LIBUSB_DT_HUB;
  non_printer->SetStringDescriptors({"", "GoogleTest", "USB Gadget 500"});

  // TODO(b/277049004): Wrap one of the above devices in a SaneDeviceFake
  // to get test coverage of the SANE devices path.

  std::vector<std::unique_ptr<UsbDevice>> device_list;
  device_list.emplace_back(std::move(non_printer));
  device_list.emplace_back(std::move(ippusb_escl_device));
  device_list.emplace_back(std::move(ippusb_printer));
  device_list.emplace_back(std::move(usb_printer));
  auto libusb = std::make_unique<LibusbWrapperFake>();
  libusb->SetDevices(std::move(device_list));

  base::test::SingleThreadTaskEnvironment task_environment;
  base::RunLoop run_loop;

  // A "socket" that can reach the fake IPP-USB scanner and the matching
  // fake SANE device to talk to it.
  auto ippusb_scanner = std::make_unique<SaneDeviceFake>();
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  auto sane_client = std::make_unique<SaneClientFake>();
  sane_client->SetIppUsbSocketDir(temp_dir.GetPath());
  base::FilePath ippusb_escl_path = temp_dir.GetPath().Append("1234-4321.sock");
  base::File ippusb_escl_socket(
      ippusb_escl_path, base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  base::FilePath ippusb_path = temp_dir.GetPath().Append("1234-6543.sock");
  base::File ippusb_socket(ippusb_path,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  sane_client->SetDeviceForName(
      "airscan:escl:GoogleTest eSCL Scanner 3000:unix://1234-4321.sock/eSCL/",
      std::move(ippusb_scanner));

  auto tracker =
      std::make_unique<DeviceTracker>(sane_client.get(), libusb.get());

  // Signal handler that tracks all the events of interest.
  std::vector<std::string> closed_sessions;
  std::set<std::unique_ptr<ScannerInfo>> scanners;
  std::string session_id;
  auto signal_handler = base::BindLambdaForTesting(
      [&run_loop, &tracker, &closed_sessions, &scanners,
       &session_id](const ScannerListChangedSignal& signal) {
        if (signal.event_type() == ScannerListChangedSignal::ENUM_COMPLETE) {
          StopScannerDiscoveryRequest stop_request;
          stop_request.set_session_id(session_id);
          tracker->StopScannerDiscovery(stop_request);
        }
        if (signal.event_type() == ScannerListChangedSignal::SESSION_ENDING) {
          closed_sessions.push_back(signal.session_id());
          run_loop.Quit();
        }
        if (signal.event_type() == ScannerListChangedSignal::SCANNER_ADDED) {
          std::unique_ptr<ScannerInfo> info(signal.scanner().New());
          info->CopyFrom(signal.scanner());
          scanners.insert(std::move(info));
        }
      });
  tracker->SetScannerListChangedSignalSender(signal_handler);

  StartScannerDiscoveryRequest start_request;
  start_request.set_client_id("ippusb");
  StartScannerDiscoveryResponse response =
      tracker->StartScannerDiscovery(start_request);
  EXPECT_TRUE(response.started());
  EXPECT_FALSE(response.session_id().empty());
  session_id = response.session_id();

  run_loop.Run();

  EXPECT_THAT(closed_sessions, ElementsAre(response.session_id()));
  ASSERT_EQ(scanners.size(), 1);
  auto& scanner = *scanners.begin();
  EXPECT_EQ(scanner->manufacturer(), "GoogleTest");
  EXPECT_EQ(scanner->model(), "eSCL Scanner 3000");
}

}  // namespace
}  // namespace lorgnette
