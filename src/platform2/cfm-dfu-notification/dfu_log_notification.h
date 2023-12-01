// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CFM_DFU_NOTIFICATION_DFU_LOG_NOTIFICATION_H_
#define CFM_DFU_NOTIFICATION_DFU_LOG_NOTIFICATION_H_

#include <string>

#include "cfm-dfu-notification/idfu_notification.h"

/**
 * Class to Implement log based notification system using the IDfuNotification
 * interface.
 */
class DfuLogNotification : public IDfuNotification {
 public:
  explicit DfuLogNotification(const std::string& device_name);

  void NotifyStartUpdate(unsigned int timeout_seconds) override;

  void NotifyEndUpdate(bool success) override;

  void NotifyUpdateProgress(float percent_done) override;

 private:
  std::string device_name_;
};

#endif  // CFM_DFU_NOTIFICATION_DFU_LOG_NOTIFICATION_H_
