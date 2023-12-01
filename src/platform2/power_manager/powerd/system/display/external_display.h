// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_EXTERNAL_DISPLAY_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_EXTERNAL_DISPLAY_H_

#include <stdint.h>

#include <memory>
#include <queue>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "power_manager/common/clock.h"

struct i2c_rdwr_ioctl_data;

namespace power_manager::system {

// Class for controlling an external display via DDC/CI.
//
// A brief summary:
//
// DDC/CI is a protocol enabling the host system to read and write various
// properties exposed by an external display over the I2C bus. This class is
// specifically interested in the display's brightness (a.k.a. luminance)
// property.
//
// DDC/CI allows the current and maximum brightness to be read by sending a
// request to the display, waiting for at least 40 milliseconds, and then
// reading the reply. It allows the brightness to be modified by sending a
// request to the display and then waiting at least 50 milliseconds before
// sending any following requests.
//
// This class caches the current brightness for a brief period of time after
// reading it from or writing it to the display; subsequent
// AdjustBrightnessByPercent() calls use that cached brightness as a starting
// point when computing new brightness levels. If an adjustment is requested
// after the cached brightness expires, the brightness is read before the update
// level is written. Multiple adjustments are coalesced when possible.
//
// This class is implemented as a simple state machine. The UpdateState() method
// is responsible for transitioning between states.
class ExternalDisplay {
 public:
  // I2C address to use for DDC/CI.
  static const uint8_t kDdcI2CAddress;

  // Address corresponding to the host.
  static const uint8_t kDdcHostAddress;

  // Address corresponding to the display.
  static const uint8_t kDdcDisplayAddress;

  // "Virtual host address" used as a starting point when checksumming replies
  // from the display (see DDC/CI v1.1 4.0).
  static const uint8_t kDdcVirtualHostAddress;

  // Mask applied to the byte containing the message body length.
  static const uint8_t kDdcMessageBodyLengthMask;

  // Opcodes for "Get VCP Feature" requests, "Get VCP Feature" replies, and "Set
  // VCP Feature" requests, respectively (per DDC/CI v1.1 4.3 and 4.4).
  static const uint8_t kDdcGetCommand;
  static const uint8_t kDdcGetReplyCommand;
  static const uint8_t kDdcSetCommand;

  // Index of the screen brightness (a.k.a. "luminance") feature.
  static const uint8_t kDdcBrightnessIndex;

  // Minimum amount of time to wait after sending a "Set VCP Feature" message
  // before sending the next message (per DDC/CI v1.1 4.4).
  static constexpr base::TimeDelta kDdcSetDelay = base::Milliseconds(50);

  // Amount of time to wait after sending a "Get VCP Feature" message before
  // reading the reply message (per DDC/CI v1.1 4.3).
  static constexpr base::TimeDelta kDdcGetDelay = base::Milliseconds(40);

  // Amount of time that the brightness value last read from or written to the
  // display should be honored before a new brightness value is read.
  static constexpr base::TimeDelta kCachedBrightnessValid = base::Seconds(3);

  // Possible outcomes when sending a message to the display. These values are
  // reported as a histogram and cannot be renumbered.
  enum class SendResult {
    // The message was successfully sent to the display.
    SUCCESS = 0,
    // The ioctl() syscall failed.
    IOCTL_FAILED = 1,
  };

  // Possible outcomes when reading a message from the display. These values are
  // reported as a histogram and cannot be renumbered.
  enum class ReceiveResult {
    // The message was successfully read from the display.
    SUCCESS = 0,
    // The ioctl() syscall failed.
    IOCTL_FAILED = 1,
    // The message had a bad checksum.
    BAD_CHECKSUM = 2,
    // The message had an unexpected source address.
    BAD_ADDRESS = 3,
    // The message body's length didn't match the expected length.
    BAD_LENGTH = 4,
    // The message body contained an unexpected command code.
    BAD_COMMAND = 5,
    // The message body contained a non-successful result code.
    BAD_RESULT = 6,
    // The message body contained an unexpected feature index.
    BAD_INDEX = 7,
    // The message body contained an unexpected maximum value of zero.
    ZERO_MAX_VALUE = 8,
  };

  // Interface that abstracts the portion of ExternalDisplay that needs to
  // communicate with devices.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Returns a name describing the I2C bus represented by this object.
    virtual std::string GetName() const = 0;

    // Performs the I2C operation described by |data| and returns true on
    // success.
    virtual bool PerformI2COperation(struct i2c_rdwr_ioctl_data* data) = 0;
  };

  // Real implementation of the Delegate interface.
  class RealDelegate : public Delegate {
   public:
    RealDelegate() = default;
    RealDelegate(const RealDelegate&) = delete;
    RealDelegate& operator=(const RealDelegate&) = delete;

    ~RealDelegate() override;

    // Initializes the object to use the I2C device at |i2c_path|.
    void Init(const base::FilePath& i2c_path);

    // Delegate implementation:
    std::string GetName() const override;
    bool PerformI2COperation(struct i2c_rdwr_ioctl_data* data) override;

   private:
    // These values are reported as a histogram and cannot be renumbered.
    enum class OpenResult {
      // Calling open() on the I2C device succeeded.
      SUCCESS = 0,
      // Calling open() on the I2C device failed with EACCES.
      FAILURE_EACCES = 1,
      // Calling open() on the I2C device failed with ENOENT.
      FAILURE_ENOENT = 2,
      // Calling open() on the I2C device failed for some other reason.
      FAILURE_UNKNOWN = 3,
    };

    // Opens |i2c_path_| and updates |fd_|.
    bool OpenI2CFile();

    // Name describing the I2C bus.
    std::string name_;

    // File descriptor corresponding to the I2C bus passed to the c'tor.
    int fd_ = -1;

    // File path for the I2C bus.
    base::FilePath i2c_path_;
  };

  // Class used by tests to interact with ExternalDisplay's internals.
  class TestApi {
   public:
    explicit TestApi(ExternalDisplay* display);
    TestApi(const TestApi&) = delete;
    TestApi& operator=(const TestApi&) = delete;

    ~TestApi() = default;

    // Advances |display_|'s clock by |interval|.
    void AdvanceTime(base::TimeDelta interval);

    // Returns the current delay for |display_|'s |timer_|.
    base::TimeDelta GetTimerDelay() const;

    // If |display_|'s |timer_| is running, stops it, executes UpdateState(),
    // and returns true. Otherwise, returns false.
    [[nodiscard]] bool TriggerTimeout();

   private:
    ExternalDisplay* display_;  // owned elsewhere
  };

  explicit ExternalDisplay(std::unique_ptr<Delegate> delegate);
  ExternalDisplay(const ExternalDisplay&) = delete;
  ExternalDisplay& operator=(const ExternalDisplay&) = delete;

  ~ExternalDisplay() = default;

  // Adjusts the display's brightness by |offset_percent|, a linearly-calculated
  // percent in the range [-100.0, 100.0]. Note that the adjustment will happen
  // asynchronously if the display's current brightness is initially unknown.
  void AdjustBrightnessByPercent(double offset_percent);

  // Adjusts the display's brightness to |percent|, a linearly-calculated
  // percent in the range [0, 100.0]. Note that this will happen asynchronously
  // if the display's current brightness is initially unknown. This operation is
  // racy if the user is simultaneously adjusting the brightness using physical
  // buttons on the display. This should not be used with displays that have
  // physical buttons for adjusting the brightness.
  void SetBrightness(double percent);

 private:
  enum class State {
    // Not currently mid-request (but if |timer_| is running, temporarily
    // blocked from sending another request due to a "set brightness" request
    // having just been sent).
    IDLE,

    // Waiting before reading the reply to a "get brightness" request.
    WAITING_FOR_REPLY,
  };

  // Returns the monitor-specific brightness level corresponding to |percent|, a
  // percentage in the range [0.0, 100.0].
  uint16_t BrightnessPercentToLevel(double percent) const;

  // Returns true if |current_brightness_percent_| and |max_brightness_level_|
  // were updated recently enough to be trusted.
  bool HaveCachedBrightness();

  // Returns true if an adjustment (in |pending_brightness_adjustment_percent_|)
  // is waiting to be applied.
  bool HavePendingBrightnessAdjustment() const;

  // Resets |timer_| to run UpdateState() after |delay|.
  void StartTimer(base::TimeDelta delay);

  // Sends a message to the display asking it to reply with the current and
  // maximum brightness. Returns true if the request was sent successfully.
  bool RequestBrightness();

  // Reads a reply from the display containing the current and maximum
  // brightness (in response to a request sent by RequestBrightness()). Returns
  // true if the brightness was read successfully.
  bool ReadBrightness();

  // Sends a message to the display asking it to update the current brightness
  // level (based on |pending_brightness_adjustment_percent_|). Returns true if
  // the request was sent successfully.
  bool WriteBrightness();

  // Examines the current value of |state_| and performs appropriate actions.
  void UpdateState();

  // Sends a DDC message containing |body| to the display.
  SendResult SendMessage(const std::vector<uint8_t>& body);

  // Receives a DDC message from the display, copying its contents to |body|.
  // |body|'s size determines the expected size of the message body.
  ReceiveResult ReceiveMessage(std::vector<uint8_t>* body);

  std::unique_ptr<Delegate> delegate_;
  Clock clock_;

  // Current state of the object.
  State state_ = State::IDLE;

  // Brightness believed to be currently used by the display, as a percentage in
  // the range [0.0, 100.0]. Note that the actual brightness may change in the
  // background, e.g. in response to the user hitting physical buttons on the
  // display.
  double current_brightness_percent_ = 0.0;

  // Maximum brightness value supported by the display, in display-specific
  // units.
  uint16_t max_brightness_level_ = 0;

  // Last time at which |current_brightness_percent_| and
  // |max_brightness_level_| were updated.
  base::TimeTicks last_brightness_update_time_;

  // Amount by which the brightness should be offset, as a percentage in the
  // range [-100.0, 100.0].
  double pending_brightness_adjustment_percent_ = 0.0;

  // Absolute brightness to set, as a percentage in the range [0.0, 100.0]. This
  // value will be less than zero if no change is pending.
  double pending_brightness_percent_ = -1.0;

  // Invokes UpdateState(). Used to enforce the mandatory delays between
  // requesting the brightness and reading the reply, and after sending a "set"
  // request to the display.
  base::OneShotTimer timer_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_EXTERNAL_DISPLAY_H_
