// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_TEST_UTIL_H_
#define CROSLOG_TEST_UTIL_H_

#include <base/time/time.h>

namespace croslog {

base::Time TimeFromExploded(int year,
                            int month,
                            int day_of_month,
                            int hour,
                            int minute,
                            int second,
                            int micro_second = 0,
                            int timezone_offset_hour = 0);

}  // namespace croslog

#endif  // CROSLOG_TEST_UTIL_H_
