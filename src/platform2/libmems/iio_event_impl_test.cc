// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <memory>
#include <tuple>

#include <base/files/file_path.h>

#include "libmems/common_types.h"
#include "libmems/iio_event_impl.h"

namespace libmems {

namespace {

class IioEventImplTestWithParam
    : public ::testing::TestWithParam<std::tuple<std::string,
                                                 iio_chan_type,
                                                 iio_event_type,
                                                 iio_event_direction,
                                                 int>> {
 protected:
  void SetUp() override {
    event_ = IioEventImpl::Create(base::FilePath(std::get<0>(GetParam())));
  }

  std::unique_ptr<IioEventImpl> event_;
};

TEST_P(IioEventImplTestWithParam, CheckTypesAndDirection) {
  EXPECT_EQ(event_->GetChannelType(), std::get<1>(GetParam()));
  EXPECT_EQ(event_->GetEventType(), std::get<2>(GetParam()));
  EXPECT_EQ(event_->GetDirection(), std::get<3>(GetParam()));
  EXPECT_EQ(event_->GetChannelNumber(), std::get<4>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    IioEventImplTestWithParamRun,
    IioEventImplTestWithParam,
    ::testing::Values(
        std::make_tuple("in_proximity0_thresh_either_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_EITHER,
                        0),
        std::make_tuple("in_proximity_thresh_rising_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_RISING,
                        0),
        std::make_tuple("in_proximity1_mag_rising_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_MAG,
                        iio_event_direction::IIO_EV_DIR_RISING,
                        1),
        std::make_tuple("in_proximity2_roc_falling_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_ROC,
                        iio_event_direction::IIO_EV_DIR_FALLING,
                        2),
        std::make_tuple("in_proximity2_thresh_adaptive_rising_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH_ADAPTIVE,
                        iio_event_direction::IIO_EV_DIR_RISING,
                        2),
        std::make_tuple("in_proximity2_mag_adaptive_falling_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_MAG_ADAPTIVE,
                        iio_event_direction::IIO_EV_DIR_FALLING,
                        2),
        std::make_tuple("in_proximity2_change_falling_en",
                        iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_CHANGE,
                        iio_event_direction::IIO_EV_DIR_FALLING,
                        2)));
}  // namespace

}  // namespace libmems
