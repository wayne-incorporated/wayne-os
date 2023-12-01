// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MBIM_CMD_H_
#define HERMES_MBIM_CMD_H_

#include <cstdint>
#include <base/check.h>
#include <base/logging.h>

class MbimCmd {
 public:
  enum MbimType : uint16_t {
    kMbimSubscriberStatusReady,
    kMbimSendApdu,
    kMbimOpenChannel,
    kMbimCloseChannel,
    kMbimDeviceCaps,
    kMbimSendEidApdu,
    kMbimSetDeviceSlotMapping,
    kMbimDeviceSlotMapping,
    kMbimSysCaps,
    kMbimSlotInfoStatus,
  };
  explicit MbimCmd(MbimType mbim_type) : mbim_type_(mbim_type) {}

  uint16_t mbim_type() { return static_cast<uint16_t>(mbim_type_); }

 private:
  MbimType mbim_type_;
};

#endif  // HERMES_MBIM_CMD_H_
