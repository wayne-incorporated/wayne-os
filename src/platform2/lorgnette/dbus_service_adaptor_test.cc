// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/dbus_service_adaptor.h"

#include <string>
#include <utility>

#include <base/test/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>
#include <sane/sane.h>

#include "lorgnette/enums.h"
#include "lorgnette/sane_client_fake.h"
#include "lorgnette/test_util.h"
#include "lorgnette/usb/libusb_wrapper.h"
#include "lorgnette/usb/libusb_wrapper_fake.h"

using ::testing::_;

namespace lorgnette {

namespace {

MATCHER_P(EqualsProto,
          message,
          "Match a proto Message equal to the matcher's argument.") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}

class MockManager : public Manager {
 public:
  MockManager(base::RepeatingCallback<void(base::TimeDelta)> callback,
              SaneClient* sane_client)
      : Manager(callback, sane_client) {}

  MOCK_METHOD(bool,
              ListScanners,
              (brillo::ErrorPtr * error,
               ListScannersResponse* scanner_list_out),
              (override));
  MOCK_METHOD(bool,
              GetScannerCapabilities,
              (brillo::ErrorPtr * error,
               const std::string& device_name,
               ScannerCapabilities* capabilities),
              (override));
  MOCK_METHOD(StartScanResponse,
              StartScan,
              (const StartScanRequest& request),
              (override));
  MOCK_METHOD(
      void,
      GetNextImage,
      (std::unique_ptr<DBusMethodResponse<GetNextImageResponse>> response,
       const GetNextImageRequest& get_next_image_request,
       const base::ScopedFD& out_fd),
      (override));
  MOCK_METHOD(CancelScanResponse,
              CancelScan,
              (const CancelScanRequest& cancel_scan_request),
              (override));
};

class MockDeviceTracker : public DeviceTracker {
 public:
  MockDeviceTracker(SaneClient* sane_client, LibusbWrapper* libusb)
      : DeviceTracker(sane_client, libusb) {}

  MOCK_METHOD(StartScannerDiscoveryResponse,
              StartScannerDiscovery,
              (const StartScannerDiscoveryRequest&),
              (override));
  MOCK_METHOD(StopScannerDiscoveryResponse,
              StopScannerDiscovery,
              (const StopScannerDiscoveryRequest&),
              (override));
};

// The adaptor functions contain no real logic and just pass through to the
// underlying implementation, which already has its own unit tests.  We can just
// test here to verify that the correct implementation function gets called for
// each d-bus entry point.

TEST(DBusServiceAdaptorTest, ListScanners) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  brillo::ErrorPtr error;
  ListScannersResponse response;
  EXPECT_CALL(*manager, ListScanners(&error, &response));
  dbus_service.ListScanners(&error, &response);
}

TEST(DBusServiceAdaptorTest, GetScannerCapabilities) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  brillo::ErrorPtr error;
  ScannerCapabilities response;
  EXPECT_CALL(*manager,
              GetScannerCapabilities(&error, "test_device", &response));
  dbus_service.GetScannerCapabilities(&error, "test_device", &response);
}

TEST(DBusServiceAdaptorTest, StartScan) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  StartScanRequest request;
  EXPECT_CALL(*manager, StartScan(EqualsProto(request)));
  dbus_service.StartScan(request);
}

TEST(DBusServiceAdaptorTest, GetNextImage) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  GetNextImageRequest request;
  std::unique_ptr<DBusMethodResponse<GetNextImageResponse>> response;
  base::ScopedFD out_fd;
  EXPECT_CALL(*manager, GetNextImage(_, EqualsProto(request), _));
  dbus_service.GetNextImage(std::move(response), request, std::move(out_fd));
}

TEST(DBusServiceAdaptorTest, CancelScan) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  CancelScanRequest request;
  EXPECT_CALL(*manager, CancelScan(EqualsProto(request)));
  dbus_service.CancelScan(request);
}

TEST(DBusServiceAdaptorTest, ToggleDebugging) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  bool callback_called = false;
  base::RepeatingCallback<void()> callback = base::BindLambdaForTesting(
      [&callback_called]() { callback_called = true; });
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service = DBusServiceAdaptor(std::unique_ptr<Manager>(manager),
                                         tracker.get(), callback);
  SetDebugConfigRequest request;
  request.set_enabled(true);
  SetDebugConfigResponse response = dbus_service.SetDebugConfig(request);
  EXPECT_TRUE(callback_called);
}

TEST(DBusServiceAdaptorTest, UnchangedDebugging) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  bool callback_called = false;
  base::RepeatingCallback<void()> callback = base::BindLambdaForTesting(
      [&callback_called]() { callback_called = true; });
  auto dbus_service = DBusServiceAdaptor(std::unique_ptr<Manager>(manager),
                                         tracker.get(), callback);
  SetDebugConfigRequest request;
  request.set_enabled(false);
  SetDebugConfigResponse response = dbus_service.SetDebugConfig(request);
  EXPECT_FALSE(callback_called);
}

TEST(DBusServiceAdaptorTest, StartScannerDiscovery) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  StartScannerDiscoveryRequest request;
  EXPECT_CALL(*tracker.get(), StartScannerDiscovery(EqualsProto(request)));
  StartScannerDiscoveryResponse response =
      dbus_service.StartScannerDiscovery(request);
  EXPECT_THAT(response, EqualsProto(StartScannerDiscoveryResponse()));
}

TEST(DBusServiceAdaptorTest, StopScannerDiscovery) {
  auto sane_client = std::make_unique<SaneClientFake>();
  auto libusb = std::make_unique<LibusbWrapperFake>();
  MockManager* manager = new MockManager({}, sane_client.get());
  auto tracker =
      std::make_unique<MockDeviceTracker>(sane_client.get(), libusb.get());
  auto dbus_service =
      DBusServiceAdaptor(std::unique_ptr<Manager>(manager), tracker.get(), {});
  StopScannerDiscoveryRequest request;
  EXPECT_CALL(*tracker.get(), StopScannerDiscovery(EqualsProto(request)));
  StopScannerDiscoveryResponse response =
      dbus_service.StopScannerDiscovery(request);
  EXPECT_THAT(response, EqualsProto(StopScannerDiscoveryResponse()));
}

}  // namespace
}  // namespace lorgnette
