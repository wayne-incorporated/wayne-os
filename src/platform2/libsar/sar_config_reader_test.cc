// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <tuple>

#include <base/strings/stringprintf.h>
#include <base/values.h>
#include <chromeos-config/libcros_config/fake_cros_config.h>

#include "libsar/sar_config_reader.h"
#include "libsar/test_fakes.h"

namespace libsar {

class SarConfigReaderTestWithParam
    : public ::testing::TestWithParam<
          std::tuple<int,                       // index of cros config file.
                     std::string,               // system-path
                     std::string,               // system-path-value
                     std::string,               // devlink
                     bool,                      // isCellular
                     bool,                      // isWifi
                     std::optional<double>>> {  // samplingFrequency
 protected:
  void SetUp() override {
    fake_cros_config_.SetString(
        base::StringPrintf("/proximity-sensor/semtech-config/%i/file",
                           std::get<0>(GetParam())),
        SarConfigReader::kSystemPathProperty, std::get<1>(GetParam()));

    delegate_.SetStringToFile(base::FilePath(std::get<1>(GetParam())),
                              std::get<2>(GetParam()));

    sar_config_reader_ = std::make_unique<SarConfigReader>(
        &fake_cros_config_, std::get<3>(GetParam()), &delegate_);
  }

  std::unique_ptr<SarConfigReader> sar_config_reader_;
  brillo::FakeCrosConfig fake_cros_config_;
  fakes::FakeSarConfigReaderDelegate delegate_;
};

TEST_P(SarConfigReaderTestWithParam, ReaderChecks) {
  EXPECT_EQ(sar_config_reader_->isCellular(), std::get<4>(GetParam()));
  EXPECT_EQ(sar_config_reader_->isWifi(), std::get<5>(GetParam()));

  auto config_dict_opt = sar_config_reader_->GetSarConfigDict();
  EXPECT_EQ(config_dict_opt.has_value(), std::get<6>(GetParam()).has_value());
  if (config_dict_opt.has_value()) {
    EXPECT_EQ(config_dict_opt->FindDouble("samplingFrequency"),
              std::get<6>(GetParam()).value());
  }
}

INSTANTIATE_TEST_SUITE_P(
    SarConfigReaderTestWithParamRun,
    SarConfigReaderTestWithParam,
    ::testing::Values(
        std::make_tuple(100,
                        "/tmp/semtech_config_cellular.json",
                        "{\"samplingFrequency\": 0}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        std::nullopt),  // Index exceeds SystemPathIndexLimit
        std::make_tuple(99,
                        "/tmp/semtech_config_cellular.json",
                        "{\"samplingFrequency\": 0}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        0),
        std::make_tuple(0,
                        "/tmp/semtech_config_cellular.json",
                        "{\"samplingFrequency\": 0}",
                        "/dev/proximity-cellular-wifi",
                        true,
                        true,
                        std::nullopt),  // System path doesn't contain wifi
        std::make_tuple(0,
                        "/tmp/semtech_config_wifi.json",
                        "{\"samplingFrequency\": 0}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        std::nullopt),  // System path doesn't contain cellular
        std::make_tuple(0,
                        "/tmp/semtech_config_cellular_wifi.json",
                        "{\"samplingFrequency: 0}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        std::nullopt),  // Invalid dict format
        std::make_tuple(0,
                        "/tmp/semtech_config_cellular.json",
                        "{\"samplingFrequency\": 100}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        100),
        std::make_tuple(1,
                        "/tmp/semtech_config_cellular.json",
                        "{\"samplingFrequency\": 100, \"dummy\": \"0\"}",
                        "/dev/proximity-cellular",
                        true,
                        false,
                        100)));

}  // namespace libsar
