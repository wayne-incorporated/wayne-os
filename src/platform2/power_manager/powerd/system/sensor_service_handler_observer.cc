// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/sensor_service_handler_observer.h"

#include "power_manager/powerd/system/sensor_service_handler.h"

namespace power_manager::system {

SensorServiceHandlerObserver::~SensorServiceHandlerObserver() {
  sensor_service_handler_->RemoveObserver(this);
}

SensorServiceHandlerObserver::SensorServiceHandlerObserver(
    SensorServiceHandler* sensor_service_handler)
    : sensor_service_handler_(sensor_service_handler) {
  sensor_service_handler_->AddObserver(this);
}

}  // namespace power_manager::system
