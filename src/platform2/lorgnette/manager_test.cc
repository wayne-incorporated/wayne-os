// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/manager.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <brillo/process/process.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>
#include <metrics/metrics_library_mock.h>
#include <sane/sane.h>

#include "lorgnette/enums.h"
#include "lorgnette/sane_client_fake.h"
#include "lorgnette/test_util.h"

using brillo::dbus_utils::MockDBusMethodResponse;
using ::testing::_;
using ::testing::ContainsRegex;
using ::testing::ElementsAre;

namespace lorgnette {

namespace {

void ValidateProgressSignals(
    const std::vector<ScanStatusChangedSignal>& signals,
    const std::string& scan_uuid) {
  int progress = 0;
  int page = 1;
  for (int i = 0; i < signals.size() - 1; i++) {
    const ScanStatusChangedSignal& signal = signals[i];
    EXPECT_EQ(signal.scan_uuid(), scan_uuid);
    EXPECT_EQ(signal.page(), page);

    if (signal.state() == SCAN_STATE_IN_PROGRESS) {
      EXPECT_GT(signal.progress(), progress);
      progress = signal.progress();
    } else if (signal.state() == SCAN_STATE_PAGE_COMPLETED) {
      page++;
      progress = 0;
    }
  }
}

void ValidateSignals(const std::vector<ScanStatusChangedSignal>& signals,
                     const std::string& scan_uuid) {
  EXPECT_GE(signals.size(), 1);
  EXPECT_EQ(signals.back().scan_uuid(), scan_uuid);
  EXPECT_EQ(signals.back().state(), SCAN_STATE_COMPLETED);

  ValidateProgressSignals(signals, scan_uuid);
}

template <typename T>
std::unique_ptr<MockDBusMethodResponse<T>> BuildMockDBusResponse(T* response) {
  auto dbus_response = std::make_unique<MockDBusMethodResponse<T>>();
  dbus_response->set_return_callback(base::BindOnce(
      [](T* response_out, const T& response_in) {
        ASSERT_TRUE(response_out);
        *response_out = response_in;
      },
      base::Unretained(response)));
  return dbus_response;
}

}  // namespace

class ManagerTest : public testing::Test {
 protected:
  ManagerTest()
      : sane_client_(new SaneClientFake()),
        manager_(base::RepeatingCallback<void(base::TimeDelta)>(),
                 sane_client_.get()),
        metrics_library_(new MetricsLibraryMock) {
    manager_.metrics_library_.reset(metrics_library_);
    manager_.SetProgressSignalInterval(base::Seconds(0));
  }

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    output_path_ = temp_dir_.GetPath().Append("scan_data");
    base::File scan(output_path_,
                    base::File::FLAG_CREATE | base::File::FLAG_WRITE);
    ASSERT_TRUE(scan.IsValid());
    scan_fd_ = base::ScopedFD(scan.TakePlatformFile());

    manager_.SetScanStatusChangedSignalSender(base::BindRepeating(
        [](std::vector<ScanStatusChangedSignal>* signals,
           const ScanStatusChangedSignal& signal) {
          signals->push_back(signal);
        },
        base::Unretained(&signals_)));
  }

  void ExpectScanRequest(DocumentScanSaneBackend backend) {
    EXPECT_CALL(*metrics_library_,
                SendEnumToUMA(Manager::kMetricScanRequested, backend,
                              DocumentScanSaneBackend::kMaxValue + 1));
  }

  void ExpectScanSuccess(DocumentScanSaneBackend backend) {
    EXPECT_CALL(*metrics_library_,
                SendEnumToUMA(Manager::kMetricScanSucceeded, backend,
                              DocumentScanSaneBackend::kMaxValue + 1));
  }

  void ExpectScanFailure(DocumentScanSaneBackend backend) {
    EXPECT_CALL(*metrics_library_,
                SendEnumToUMA(Manager::kMetricScanFailed, backend,
                              DocumentScanSaneBackend::kMaxValue + 1));
  }

  void ExpectScanFailureReason(ScanJobFailureReason failure_reason) {
    EXPECT_CALL(*metrics_library_,
                SendEnumToUMA(Manager::kMetricScanFailedFailureReason,
                              static_cast<int>(failure_reason), _));
  }

  void CompareImages(const std::string& path_a, const std::string& path_b) {
    brillo::ProcessImpl diff;
    diff.AddArg("/usr/bin/perceptualdiff");
    diff.AddArg("-verbose");
    diff.AddIntOption("-threshold", 1);
    diff.AddArg(path_a);
    diff.AddArg(path_b);
    EXPECT_EQ(diff.Run(), 0)
        << path_a << " and " << path_b << " are not the same image";
  }

  void SetUpTestDevice(
      const std::string& name,
      const std::vector<base::FilePath>& image_paths,
      const ScanParameters& parameters,
      const SANE_Status& read_scan_data_result = SANE_STATUS_GOOD) {
    std::vector<std::vector<uint8_t>> pages;
    for (const base::FilePath& path : image_paths) {
      std::string contents;
      ASSERT_TRUE(base::ReadFileToString(path, &contents));
      std::vector<uint8_t> image_data(contents.begin(), contents.end());
      pages.push_back(image_data);
    }

    std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
    device->SetScanData(pages);
    device->SetScanParameters(parameters);
    device->SetReadScanDataResult(read_scan_data_result);
    sane_client_->SetDeviceForName(name, std::move(device));
  }

  // Set up a multi-page color scan.
  void SetUpMultiPageScan() {
    ScanParameters parameters;
    parameters.format = kRGB;
    parameters.bytes_per_line = 98 * 3;
    parameters.pixels_per_line = 98;
    parameters.lines = 50;
    parameters.depth = 8;
    base::FilePath path("test_images/color.pnm");
    SetUpTestDevice("TestDevice", {path, path}, parameters);
  }

  StartScanResponse StartScan(const std::string& device_name,
                              ColorMode color_mode,
                              const std::string& source_name,
                              ImageFormat image_format) {
    StartScanRequest request;
    request.set_device_name(device_name);
    request.mutable_settings()->set_color_mode(color_mode);
    request.mutable_settings()->set_source_name(source_name);
    request.mutable_settings()->set_image_format(image_format);
    return manager_.StartScan(request);
  }

  GetNextImageResponse GetNextImage(const std::string& scan_uuid,
                                    const base::ScopedFD& output_fd) {
    GetNextImageRequest request;
    request.set_scan_uuid(scan_uuid);

    GetNextImageResponse response;
    manager_.GetNextImage(BuildMockDBusResponse(&response), request, output_fd);
    return response;
  }

  CancelScanResponse CancelScan(const std::string& scan_uuid) {
    CancelScanRequest request;
    request.set_scan_uuid(scan_uuid);
    return manager_.CancelScan(request);
  }

  // Run a one-page scan to completion, and verify that it was successful.
  void RunScanSuccess(const std::string& device_name,
                      ColorMode color_mode,
                      ImageFormat image_format) {
    StartScanResponse response =
        StartScan(device_name, color_mode, "Flatbed", image_format);
    EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
    EXPECT_NE(response.scan_uuid(), "");

    GetNextImageResponse get_next_image_response =
        GetNextImage(response.scan_uuid(), scan_fd_);
    EXPECT_TRUE(get_next_image_response.success());

    ValidateSignals(signals_, response.scan_uuid());
  }

  std::vector<ScanStatusChangedSignal> signals_;

  std::unique_ptr<SaneClientFake> sane_client_;
  Manager manager_;
  MetricsLibraryMock* metrics_library_;  // Owned by manager_.
  base::ScopedTempDir temp_dir_;
  base::FilePath output_path_;
  base::ScopedFD scan_fd_;
};

TEST_F(ManagerTest, ListScannerSuccess) {
  brillo::ErrorPtr error;
  sane_client_->AddDevice("TestName", "TestMaker", "TestModel", "TestType");
  sane_client_->SetListDevicesResult(true);
  std::optional<std::vector<ScannerInfo>> result =
      sane_client_->ListDevices(&error);
  EXPECT_EQ(error, nullptr);
  EXPECT_NE(result, std::nullopt);
  EXPECT_EQ(result.value().size(), 1);
  sane_client_->RemoveDevice("TestName");
  result = sane_client_->ListDevices(&error);
  EXPECT_NE(result, std::nullopt);
  EXPECT_EQ(result.value().size(), 0);
  EXPECT_EQ(error, nullptr);
}

TEST_F(ManagerTest, ListScannersFailure) {
  brillo::ErrorPtr error;
  sane_client_->SetListDevicesResult(false);
  std::optional<std::vector<ScannerInfo>> result =
      sane_client_->ListDevices(&error);
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(ManagerTest, GetColorModeFromDevice) {
  brillo::ErrorPtr error;
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetColorMode(&error, MODE_COLOR);
  std::optional<ColorMode> color_mode = device->GetColorMode(&error);
  EXPECT_NE(color_mode, std::nullopt);
  EXPECT_EQ(color_mode.value(), MODE_COLOR);
}

TEST_F(ManagerTest, GetScannerCapabilitiesInvalidIppUsbFailure) {
  ScannerCapabilities response;
  brillo::ErrorPtr error;
  EXPECT_FALSE(
      manager_.GetScannerCapabilities(&error, "ippusb:invalid", &response));
  EXPECT_NE(error, nullptr);
  EXPECT_NE(error->GetMessage().find("ippusb"), std::string::npos);
}

TEST_F(ManagerTest, GetScannerCapabilitiesSuccess) {
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  ValidOptionValues opts;
  opts.resolutions = {50, 100, 200, 300, 500, 600};
  opts.sources = {
      CreateDocumentSource("FB", SOURCE_PLATEN, 355.2, 417.9, {75, 150},
                           {MODE_COLOR}),
      CreateDocumentSource("Negative", SOURCE_UNSPECIFIED, 355.2, 204.0,
                           {200, 300, 600}, {MODE_GRAYSCALE}),
      CreateDocumentSource("Automatic Document Feeder", SOURCE_ADF_SIMPLEX,
                           212.9, 212.2, {100, 200}, {MODE_GRAYSCALE})};
  opts.color_modes = {kScanPropertyModeColor};
  device->SetValidOptionValues(opts);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ScannerCapabilities caps;
  EXPECT_TRUE(manager_.GetScannerCapabilities(nullptr, "TestDevice", &caps));

  EXPECT_THAT(caps.resolutions(), ElementsAre(100, 200, 300, 600));

  EXPECT_THAT(caps.sources(),
              ElementsAre(EqualsDocumentSource(CreateDocumentSource(
                              "FB", SOURCE_PLATEN, 355.2, 417.9, {75, 150},
                              {MODE_COLOR})),
                          EqualsDocumentSource(CreateDocumentSource(
                              "Automatic Document Feeder", SOURCE_ADF_SIMPLEX,
                              212.9, 212.2, {100, 200}, {MODE_GRAYSCALE}))));

  EXPECT_THAT(caps.color_modes(), ElementsAre(MODE_COLOR));
}

TEST_F(ManagerTest, StartScanPngBlackAndWhiteSuccess) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_LINEART, IMAGE_FORMAT_PNG);
  CompareImages("./test_images/bw.png", output_path_.value());
}

TEST_F(ManagerTest, StartScanPngGrayscaleSuccess) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.pixels_per_line = 32;
  parameters.lines = 32;
  parameters.depth = 8;
  parameters.bytes_per_line = parameters.pixels_per_line * parameters.depth / 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/gray.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_GRAYSCALE, IMAGE_FORMAT_PNG);
  CompareImages("./test_images/gray.png", output_path_.value());
}

TEST_F(ManagerTest, StartScanPngColorSuccess) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 98 * 3;
  parameters.pixels_per_line = 98;
  parameters.lines = 50;
  parameters.depth = 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_COLOR, IMAGE_FORMAT_PNG);
  CompareImages("./test_images/color.png", output_path_.value());
}

TEST_F(ManagerTest, StartScanPng16BitColorSuccess) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.pixels_per_line = 32;
  parameters.lines = 32;
  parameters.depth = 16;
  parameters.bytes_per_line =
      parameters.pixels_per_line * parameters.depth / 8 * 3;
  // Note: technically, color16.pnm does not really contain PNM data, since
  // NetPBM assumes big endian 16-bit samples. Since SANE provides
  // endian-native samples, color16.pnm stores the samples as little-endian.
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color16.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_COLOR, IMAGE_FORMAT_PNG);
  CompareImages("./test_images/color16.png", output_path_.value());
}

TEST_F(ManagerTest, StartScanJpegBlackAndWhiteSuccess) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_LINEART, IMAGE_FORMAT_JPEG);
  CompareImages("./test_images/bw.jpeg", output_path_.value());
}

TEST_F(ManagerTest, StartScanJpegGrayscaleSuccess) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.pixels_per_line = 32;
  parameters.lines = 32;
  parameters.depth = 8;
  parameters.bytes_per_line = parameters.pixels_per_line * parameters.depth / 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/gray.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_GRAYSCALE, IMAGE_FORMAT_JPEG);
  CompareImages("./test_images/gray.jpeg", output_path_.value());
}

TEST_F(ManagerTest, StartScanJpegColorSuccess) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 98 * 3;
  parameters.pixels_per_line = 98;
  parameters.lines = 50;
  parameters.depth = 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  RunScanSuccess("TestDevice", MODE_COLOR, IMAGE_FORMAT_JPEG);
  CompareImages("./test_images/color.jpeg", output_path_.value());
}

TEST_F(ManagerTest, StartScanMultiPageColorSuccess) {
  SetUpMultiPageScan();
  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);

  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "ADF", IMAGE_FORMAT_PNG);
  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  CompareImages("./test_images/color.png", output_path_.value());

  base::FilePath second_page = temp_dir_.GetPath().Append("scan_data2.png");
  base::File scan(second_page,
                  base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  ASSERT_TRUE(scan.IsValid());
  base::ScopedFD second_page_fd(scan.TakePlatformFile());

  get_next_image_response = GetNextImage(response.scan_uuid(), second_page_fd);
  EXPECT_TRUE(get_next_image_response.success());
  CompareImages("./test_images/color.png", second_page.value());

  ValidateSignals(signals_, response.scan_uuid());
}

TEST_F(ManagerTest, StartScanCancelledImmediately) {
  SetUpMultiPageScan();

  ExpectScanRequest(kOtherBackend);
  // Set the source to "ADF" so that lorgnette knows to expect multiple pages.
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "ADF", IMAGE_FORMAT_PNG);
  std::string uuid = response.scan_uuid();
  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(uuid, "");

  CancelScanResponse cancel_scan_response = CancelScan(uuid);
  EXPECT_TRUE(cancel_scan_response.success());

  GetNextImageResponse get_next_image_response = GetNextImage(uuid, scan_fd_);
  EXPECT_FALSE(get_next_image_response.success());

  EXPECT_EQ(signals_.back().scan_uuid(), uuid);
  EXPECT_EQ(signals_.back().state(), SCAN_STATE_CANCELLED);
  ValidateProgressSignals(signals_, uuid);
}

TEST_F(ManagerTest, StartScanCancelledWithNoFurtherOperations) {
  SetUpMultiPageScan();

  ExpectScanRequest(kOtherBackend);
  // Set the source to "ADF" so that lorgnette knows to expect multiple pages.
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "ADF", IMAGE_FORMAT_PNG);
  std::string uuid = response.scan_uuid();
  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(uuid, "");

  CancelScanResponse cancel_scan_response = CancelScan(uuid);
  EXPECT_TRUE(cancel_scan_response.success());

  EXPECT_EQ(signals_.back().scan_uuid(), uuid);
  EXPECT_EQ(signals_.back().state(), SCAN_STATE_CANCELLED);
  ValidateProgressSignals(signals_, uuid);
}

TEST_F(ManagerTest, StartScanCancelledAfterGettingPage) {
  SetUpMultiPageScan();

  ExpectScanRequest(kOtherBackend);
  // Set the source to "ADF" so that lorgnette knows to expect multiple pages.
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "ADF", IMAGE_FORMAT_PNG);
  std::string uuid = response.scan_uuid();
  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(uuid, "");

  GetNextImageResponse get_next_image_response = GetNextImage(uuid, scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  CancelScanResponse cancel_scan_response = CancelScan(uuid);
  EXPECT_TRUE(cancel_scan_response.success());

  get_next_image_response = GetNextImage(uuid, scan_fd_);
  EXPECT_FALSE(get_next_image_response.success());

  EXPECT_EQ(signals_.back().scan_uuid(), uuid);
  EXPECT_EQ(signals_.back().state(), SCAN_STATE_CANCELLED);
  ValidateProgressSignals(signals_, uuid);
}

TEST_F(ManagerTest, StartScanFailNoDevice) {
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanFailToStart) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetStartScanResult(SANE_STATUS_IO_ERROR);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kIoError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_IO_ERROR);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanDeviceBusy) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetStartScanResult(SANE_STATUS_DEVICE_BUSY);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kDeviceBusy);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_DEVICE_BUSY);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanAdfJammed) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetStartScanResult(SANE_STATUS_JAMMED);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kAdfJammed);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_ADF_JAMMED);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanAdfEmpty) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetStartScanResult(SANE_STATUS_NO_DOCS);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kAdfEmpty);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_ADF_EMPTY);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanFlatbedOpen) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetStartScanResult(SANE_STATUS_COVER_OPEN);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kFlatbedOpen);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_FAILED);
  EXPECT_NE(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_FLATBED_OPEN);
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, StartScanFailToRead) {
  std::string contents;
  ASSERT_TRUE(base::ReadFileToString(base::FilePath("./test_images/color.pnm"),
                                     &contents));
  std::vector<uint8_t> image_data(contents.begin(), contents.end());
  std::unique_ptr<SaneDeviceFake> device = std::make_unique<SaneDeviceFake>();
  device->SetScanData({image_data});
  device->SetReadScanDataResult(SANE_STATUS_IO_ERROR);
  sane_client_->SetDeviceForName("TestDevice", std::move(device));

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_NE(signals_[0].failure_reason(), "");
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, GetNextImageDeviceBusy) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters, SANE_STATUS_DEVICE_BUSY);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kDeviceBusy);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_NE(signals_[0].failure_reason(), "");
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_DEVICE_BUSY);
}

TEST_F(ManagerTest, GetNextImageAdfJammed) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters, SANE_STATUS_JAMMED);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kAdfJammed);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_NE(signals_[0].failure_reason(), "");
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_ADF_JAMMED);
}

TEST_F(ManagerTest, GetNextImageFlatbedOpen) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters, SANE_STATUS_COVER_OPEN);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kFlatbedOpen);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_NE(signals_[0].failure_reason(), "");
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_FLATBED_OPEN);
}

TEST_F(ManagerTest, GetNextImageIoError) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 11;
  parameters.pixels_per_line = 85;
  parameters.lines = 29;
  parameters.depth = 1;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/bw.pnm")},
                  parameters, SANE_STATUS_IO_ERROR);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kIoError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_NE(signals_[0].failure_reason(), "");
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_IO_ERROR);
}

TEST_F(ManagerTest, GetNextImageBadFd) {
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  ScanParameters());

  ExpectScanRequest(kOtherBackend);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), base::ScopedFD());
  EXPECT_FALSE(get_next_image_response.success());
  EXPECT_NE(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_UNKNOWN);

  // Scan should not have failed.
  EXPECT_EQ(signals_.size(), 0);
}

TEST_F(ManagerTest, GetNextImageScanAlreadyComplete) {
  ScanParameters parameters;
  parameters.format = kGrayscale;
  parameters.pixels_per_line = 32;
  parameters.lines = 32;
  parameters.depth = 8;
  parameters.bytes_per_line = parameters.pixels_per_line * parameters.depth / 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/gray.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanSuccess(kOtherBackend);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "ADF", IMAGE_FORMAT_PNG);
  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  CompareImages("./test_images/gray.png", output_path_.value());

  get_next_image_response = GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_FALSE(get_next_image_response.success());

  ValidateSignals(signals_, response.scan_uuid());
}

TEST_F(ManagerTest, GetNextImageNegativeWidth) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 100;
  parameters.pixels_per_line = -1;
  parameters.lines = 11;
  parameters.depth = 16;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_EQ(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_NO_FAILURE);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  EXPECT_EQ(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_NO_FAILURE);

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_THAT(signals_[0].failure_reason(), ContainsRegex("invalid width"));
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, GetNextImageExcessWidth) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 3000003;
  parameters.pixels_per_line = 1000001;
  parameters.lines = 100;
  parameters.depth = 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_EQ(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_NO_FAILURE);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  EXPECT_EQ(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_NO_FAILURE);

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_THAT(signals_[0].failure_reason(), ContainsRegex("invalid width"));
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, GetNextImageInvalidHeight) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 0x40000000 + (0x10 * 0x08);
  parameters.pixels_per_line = 0x10;
  parameters.lines = 0x02000000;
  parameters.depth = 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_EQ(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_NO_FAILURE);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  EXPECT_EQ(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_NO_FAILURE);

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_THAT(signals_[0].failure_reason(), ContainsRegex("invalid height"));
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, GetNextImageMismatchedSizes) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 8.5 * 1200;
  parameters.pixels_per_line = 8.5 * 1200;
  parameters.lines = 11 * 1200;
  parameters.depth = 8;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_EQ(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_NO_FAILURE);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  EXPECT_EQ(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_NO_FAILURE);

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_THAT(signals_[0].failure_reason(),
              ContainsRegex("bytes_per_line.*too small"));
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, GetNextImageTooLarge) {
  ScanParameters parameters;
  parameters.format = kRGB;
  parameters.bytes_per_line = 8.5 * 1200 * 6;
  parameters.pixels_per_line = 8.5 * 1200;
  parameters.lines = 11 * 1200;
  parameters.depth = 16;
  SetUpTestDevice("TestDevice", {base::FilePath("./test_images/color.pnm")},
                  parameters);

  ExpectScanRequest(kOtherBackend);
  ExpectScanFailure(kOtherBackend);
  ExpectScanFailureReason(ScanJobFailureReason::kUnknownScannerError);
  StartScanResponse response =
      StartScan("TestDevice", MODE_COLOR, "Flatbed", IMAGE_FORMAT_PNG);

  EXPECT_EQ(response.state(), SCAN_STATE_IN_PROGRESS);
  EXPECT_EQ(response.failure_reason(), "");
  EXPECT_EQ(response.scan_failure_mode(), SCAN_FAILURE_MODE_NO_FAILURE);
  EXPECT_NE(response.scan_uuid(), "");

  GetNextImageResponse get_next_image_response =
      GetNextImage(response.scan_uuid(), scan_fd_);
  EXPECT_TRUE(get_next_image_response.success());
  EXPECT_EQ(get_next_image_response.failure_reason(), "");
  EXPECT_EQ(get_next_image_response.scan_failure_mode(),
            SCAN_FAILURE_MODE_NO_FAILURE);

  EXPECT_EQ(signals_.size(), 1);
  EXPECT_EQ(signals_[0].scan_uuid(), response.scan_uuid());
  EXPECT_EQ(signals_[0].state(), SCAN_STATE_FAILED);
  EXPECT_THAT(signals_[0].failure_reason(),
              ContainsRegex("scan buffer.*too large"));
  EXPECT_EQ(signals_[0].scan_failure_mode(), SCAN_FAILURE_MODE_UNKNOWN);
}

TEST_F(ManagerTest, RemoveDupNoRepeats) {
  std::vector<ScannerInfo> scanners_empty, scanners_present, sane_scanners,
      expected_present;
  base::flat_set<std::string> seen_vidpid, seen_busdev;

  ScannerInfo pixma, epson, fujitsu;
  pixma.set_name("pixma:1a492785_265798");
  epson.set_name("epson2:libusb:004:007");
  fujitsu.set_name("fujitsu:ScanSnap iX500:1603948");
  sane_scanners.push_back(pixma);
  sane_scanners.push_back(epson);
  sane_scanners.push_back(fujitsu);
  // first make sure it doesn't crash with no seen scanners
  manager_.RemoveDuplicateScanners(&scanners_empty, seen_vidpid, seen_busdev,
                                   sane_scanners);
  EXPECT_EQ(scanners_empty.size(), sane_scanners.size());
  for (int s = 0; s < scanners_empty.size(); s++) {
    EXPECT_EQ(scanners_empty[s].name(), sane_scanners[s].name());
  }
  // now make sure it works with seen scanners and no match
  ScannerInfo ippusb1, ippusb2;
  ippusb1.set_name("ippusb:escl:EPSON XP-7100 Series:05a8_1134/eSCL/");
  ippusb2.set_name("ippusb:escl:Brother HL-L2539DW series:05d9_0023/eSCL/");
  scanners_present.push_back(ippusb1);
  expected_present.push_back(ippusb1);
  scanners_present.push_back(ippusb2);
  expected_present.push_back(ippusb2);
  seen_vidpid.insert("05a8:1134");
  seen_vidpid.insert("05d9:0023");
  seen_busdev.insert("006:006");
  seen_busdev.insert("001:003");
  manager_.RemoveDuplicateScanners(&scanners_present, seen_vidpid, seen_busdev,
                                   sane_scanners);
  expected_present.push_back(pixma);
  expected_present.push_back(epson);
  expected_present.push_back(fujitsu);
  EXPECT_EQ(scanners_present.size(), expected_present.size());
  for (int s = 0; s < scanners_present.size(); s++) {
    EXPECT_EQ(scanners_present[s].name(), expected_present[s].name());
  }
}

TEST_F(ManagerTest, RemoveDupWithRepeats) {
  std::vector<ScannerInfo> scanners_present, sane_scanners, expected_present;
  base::flat_set<std::string> seen_vidpid, seen_busdev;
  ScannerInfo ipp_pixma, sane_pixma, ipp_epson, sane_epson, sane_fujitsu;

  ipp_pixma.set_name("ippusb:escl:Canon TR8500 series:05d9_0023/eSCL/");
  seen_vidpid.insert("05d9:0023");
  seen_busdev.insert("001:005");
  scanners_present.push_back(ipp_pixma);
  expected_present.push_back(ipp_pixma);
  ipp_epson.set_name("ippusb:escl:EPSON XP-7100 Series:05a8_1134/eSCL/");
  seen_vidpid.insert("05a8:1134");
  seen_busdev.insert("004:007");
  scanners_present.push_back(ipp_epson);
  expected_present.push_back(ipp_epson);

  sane_pixma.set_name("pixma:05d90023_265798");
  sane_epson.set_name("epson2:libusb:004:007");
  sane_fujitsu.set_name("fujitsu:ScanSnap iX500:1603948");
  sane_scanners.push_back(sane_pixma);
  sane_scanners.push_back(sane_epson);
  sane_scanners.push_back(sane_fujitsu);
  manager_.RemoveDuplicateScanners(&scanners_present, seen_vidpid, seen_busdev,
                                   sane_scanners);
  expected_present.push_back(sane_fujitsu);

  EXPECT_EQ(scanners_present.size(), expected_present.size());
  for (int s = 0; s < scanners_present.size(); s++) {
    EXPECT_EQ(scanners_present[s].name(), expected_present[s].name());
  }
}

TEST_F(ManagerTest, UsableScannerInfo) {
  ScannerInfo scanner;
  scanner.set_name(
      "airscan:escl:Canon MF260 II Series:http://192.168.0.100/eSCL/");
  scanner.set_manufacturer("CANON");
  scanner.set_model("MF260 II Series");

  EXPECT_TRUE(Manager::ScannerCanBeUsed(scanner));
}

TEST_F(ManagerTest, UnusableScannerInfo) {
  ScannerInfo net_scanner;
  net_scanner.set_name("pixma:MF260_192.168.0.100");
  net_scanner.set_manufacturer("CANON");
  net_scanner.set_model("MF260 II Series");

  ScannerInfo usb_scanner;
  usb_scanner.set_name("pixma:05d90023_265798");
  usb_scanner.set_manufacturer("CANON");
  usb_scanner.set_model("MF260 II Series");

  ScannerInfo usb_scanner_variant;
  usb_scanner_variant.set_name("pixma:05d90023_265798");
  usb_scanner_variant.set_manufacturer("CANON");
  usb_scanner_variant.set_model("MF 260 II Series");

  EXPECT_FALSE(Manager::ScannerCanBeUsed(net_scanner));
  EXPECT_FALSE(Manager::ScannerCanBeUsed(usb_scanner));
  EXPECT_FALSE(Manager::ScannerCanBeUsed(usb_scanner_variant));
}

TEST(BackendFromDeviceName, IppUsbAndAirscan) {
  std::vector<std::pair<std::string, DocumentScanSaneBackend>> cases = {
      {"airscan:escl:HP LaserJet 4:http://192.168.0.15:80/eSCL/", kAirscanHp},
      {"airscan:escl:Hewlett-Packard Scanjet Pro 2000:http://localhost/eSCL/",
       kAirscanHp},
      {"airscan:escl:HewlettPackard Scanjet Pro 2000:http://localhost/eSCL/",
       kAirscanHp},
      {"airscan:wsd:Konica Minolta Bizhub 3622:http://192.168.0.15:443/eSCL/",
       kAirscanKonicaMinolta},
      {"airscan:escl:RicohPrinter:http://192.168.0.15:80/eSCL/", kAirscanOther},
      {"airscan", kAirscanOther},
      {"ippusb:escl:EPSON XP-7100 Series:05a8_1134/eSCL/", kIppUsbEpson},
      {"ippusb:escl:Hewlett Packard Scanjet N6310:05a8_1134/eSCL/", kIppUsbHp},
      {"ippusb:escl:Lexmark Lexmark MB2236adwe:05a8_1134/eSCL/",
       kIppUsbLexmark},
      {"ippusb:escl:Scanner Kodak i3250:05a8_1134/eSCL/", kIppUsbKodak},
      {"ippusb:escl:Ye Olde Unbranded Scanner:05a8_1134/eSCL/", kIppUsbOther},
      {"ippusb", kIppUsbOther},
  };

  for (const auto& [device_name, expected_backend] : cases) {
    EXPECT_EQ(BackendFromDeviceName(device_name), expected_backend)
        << "Expected backend for device " << device_name << " was not correct.";
  }
}

}  // namespace lorgnette
