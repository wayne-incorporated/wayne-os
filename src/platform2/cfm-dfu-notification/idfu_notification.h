// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CFM_DFU_NOTIFICATION_IDFU_NOTIFICATION_H_
#define CFM_DFU_NOTIFICATION_IDFU_NOTIFICATION_H_

#include <memory>
#include <string>

#include <brillo/brillo_export.h>

/**
 * Interface to expose the DFU Notification to the Updaters.
 */
class BRILLO_EXPORT IDfuNotification {
 public:
  static constexpr unsigned int kDefaultTimeoutSeconds = 300;

  /*
   * @brief Creates an instance of the DfuNotification for particular device.
   * @param device_name Name of the device to be shown in the UI.
   * @return An instance of the notification object to be used for notifying.
   */
  static std::unique_ptr<IDfuNotification> For(const std::string& device_name);

  /*
   * @brief Notifies the start of an update.
   * @param timeout_s Timeout in seconds after which the Notification should be
   *        removed even if no end update is received.
   */
  virtual void NotifyStartUpdate(
      unsigned int timeout_seconds = kDefaultTimeoutSeconds) = 0;

  /*
   * @brief Notifies the end of an update.
   * @param success True if the updated succeeded otherwise false.
   */
  virtual void NotifyEndUpdate(bool success) = 0;

  /*
   * @brief Notifies the progress of an update.
   * @param percent_done The amount of the update completed as a float [0-1]
   */
  virtual void NotifyUpdateProgress(float percent_done) = 0;

  virtual ~IDfuNotification() = default;
};

#endif  // CFM_DFU_NOTIFICATION_IDFU_NOTIFICATION_H_
