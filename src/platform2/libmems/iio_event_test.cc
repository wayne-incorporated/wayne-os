// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "libmems/common_types.h"
#include "libmems/test_fakes.h"

namespace libmems {

namespace {

class IioEventTestOnMatchMaskWithParam
    : public ::testing::TestWithParam<std::tuple<iio_chan_type,
                                                 iio_event_type,
                                                 iio_event_direction,
                                                 int,
                                                 uint64_t,
                                                 bool>> {
 protected:
  void SetUp() override {
    event_ = std::make_unique<libmems::fakes::FakeIioEvent>(
        std::get<0>(GetParam()), std::get<1>(GetParam()),
        std::get<2>(GetParam()), std::get<3>(GetParam()));
  }

  std::unique_ptr<libmems::fakes::FakeIioEvent> event_;
};

TEST_P(IioEventTestOnMatchMaskWithParam, MatchMask) {
  EXPECT_EQ(event_->MatchMask(std::get<4>(GetParam())),
            std::get<5>(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(
    IioEventTestOnMatchMaskWithParamRun,
    IioEventTestOnMatchMaskWithParam,
    ::testing::Values(
        std::make_tuple(iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_EITHER,
                        0,
                        0,
                        false),
        std::make_tuple(iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_EITHER,
                        0,
                        IioEventCode(iio_chan_type::IIO_PROXIMITY,
                                     iio_event_type::IIO_EV_TYPE_MAG,
                                     iio_event_direction::IIO_EV_DIR_EITHER,
                                     0),
                        false),
        std::make_tuple(iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_EITHER,
                        0,
                        IioEventCode(iio_chan_type::IIO_PROXIMITY,
                                     iio_event_type::IIO_EV_TYPE_THRESH,
                                     iio_event_direction::IIO_EV_DIR_EITHER,
                                     0),
                        true),
        std::make_tuple(iio_chan_type::IIO_PROXIMITY,
                        iio_event_type::IIO_EV_TYPE_THRESH,
                        iio_event_direction::IIO_EV_DIR_EITHER,
                        0,
                        IioEventCode(iio_chan_type::IIO_PROXIMITY,
                                     iio_event_type::IIO_EV_TYPE_THRESH,
                                     iio_event_direction::IIO_EV_DIR_RISING,
                                     0),
                        true)));

}  // namespace

}  // namespace libmems
