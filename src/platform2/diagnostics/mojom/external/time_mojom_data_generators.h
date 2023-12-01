// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_DATA_GENERATORS_H_
#define DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_DATA_GENERATORS_H_

#include <memory>

#include <base/time/time.h>

#include "diagnostics/bindings/connectivity/data_generator.h"

namespace diagnostics {

class BaseTimeGenerator
    : public ash::cros_healthd::connectivity::DataGeneratorInterface<
          base::Time> {
 public:
  BaseTimeGenerator(const BaseTimeGenerator&) = delete;
  BaseTimeGenerator& operator=(const BaseTimeGenerator&) = delete;
  virtual ~BaseTimeGenerator() = default;

  static std::unique_ptr<BaseTimeGenerator> Create(
      ash::cros_healthd::connectivity::Context*) {
    return std::unique_ptr<BaseTimeGenerator>(new BaseTimeGenerator());
  }

 public:
  base::Time Generate() override;

  bool HasNext() override { return has_next_; }

 protected:
  BaseTimeGenerator() = default;

 private:
  bool has_next_ = true;
};

class BaseTimeDeltaGenerator
    : public ash::cros_healthd::connectivity::DataGeneratorInterface<
          base::TimeDelta> {
 public:
  BaseTimeDeltaGenerator(const BaseTimeDeltaGenerator&) = delete;
  BaseTimeDeltaGenerator& operator=(const BaseTimeDeltaGenerator&) = delete;
  virtual ~BaseTimeDeltaGenerator() = default;

  static std::unique_ptr<BaseTimeDeltaGenerator> Create(
      ash::cros_healthd::connectivity::Context*) {
    return std::unique_ptr<BaseTimeDeltaGenerator>(
        new BaseTimeDeltaGenerator());
  }

 public:
  base::TimeDelta Generate() override;

  bool HasNext() override { return has_next_; }

 protected:
  BaseTimeDeltaGenerator() = default;

 private:
  bool has_next_ = true;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_MOJOM_EXTERNAL_TIME_MOJOM_DATA_GENERATORS_H_
