// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_COMMON_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_COMMON_H_

#include <sstream>
#include <string>

#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

std::string GetDeviceTypesInString() {
  std::stringstream ss;
  for (int i = 0; i <= static_cast<int32_t>(cros::mojom::DeviceType::kMaxValue);
       ++i) {
    if (i != 0)
      ss << ", ";
    auto type = static_cast<cros::mojom::DeviceType>(i);
    ss << type << ": " << i;
  }

  return ss.str();
}

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_COMMON_H_
