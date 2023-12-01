// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TIMBERSLIDE_MOCK_TIMBERSLIDE_H_
#define TIMBERSLIDE_MOCK_TIMBERSLIDE_H_

#include <memory>
#include <utility>

#include "timberslide/string_transformer.h"
#include "timberslide/timberslide.h"

namespace timberslide {

class MockTimberSlide : public TimberSlide {
 public:
  explicit MockTimberSlide(std::unique_ptr<LogListener> log_listener = nullptr)
      : TimberSlide(std::move(log_listener),
                    std::make_unique<StringTransformer>()) {}
  ~MockTimberSlide() override = default;
  MOCK_METHOD(bool, GetEcUptime, (int64_t*), (override));
};

}  // namespace timberslide

#endif  // TIMBERSLIDE_MOCK_TIMBERSLIDE_H_
