// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/display/external_display.h"

#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>

#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/compiler_specific.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

// Returns a two-character hexadecimal representation of |byte|.
std::string Hex(uint8_t byte) {
  return base::HexEncode(&byte, 1);
}

// Test implementation of ExternalDisplay::Delegate.
class TestDelegate : public ExternalDisplay::Delegate {
 public:
  TestDelegate() = default;
  TestDelegate(const TestDelegate&) = delete;
  TestDelegate& operator=(const TestDelegate&) = delete;

  ~TestDelegate() override = default;

  void set_reply_message(const std::vector<uint8_t>& message) {
    reply_message_ = message;
  }
  void set_report_write_failure(bool failure) {
    report_write_failure_ = failure;
  }
  void set_report_read_failure(bool failure) { report_read_failure_ = failure; }

  // Returns the single message present in |sent_messages_|, if any, and clears
  // the vector. Crashes if multiple messages are present.
  std::string PopSentMessage() {
    std::string message;
    CHECK_LE(sent_messages_.size(), 1u);
    if (!sent_messages_.empty())
      message = sent_messages_[0];
    sent_messages_.clear();
    return message;
  }

  // ExternalDisplay::Delegate implementation:
  std::string GetName() const override { return "i2c-test"; }

  bool PerformI2COperation(struct i2c_rdwr_ioctl_data* data) override {
    // Check that the passed-in data is remotely sane.
    CHECK(data);
    CHECK_EQ(data->nmsgs, 1u);
    struct i2c_msg* const i2c_message = data->msgs;
    CHECK(i2c_message);
    CHECK(i2c_message->buf);
    uint8_t* const message = i2c_message->buf;
    const size_t message_length = i2c_message->len;
    CHECK(message);
    CHECK_GT(message_length, 0u);

    if (i2c_message->addr != ExternalDisplay::kDdcI2CAddress) {
      LOG(ERROR) << "Ignoring operation with I2C address " << i2c_message->addr;
      return false;
    }

    // Write request.
    if (i2c_message->flags == 0) {
      if (report_write_failure_)
        return false;

      sent_messages_.push_back(base::HexEncode(message, message_length));
      return true;
    }

    // Read request.
    if (i2c_message->flags == I2C_M_RD) {
      if (report_read_failure_)
        return false;

      if (message_length != reply_message_.size()) {
        LOG(ERROR) << "Got request to read " << message_length << " byte(s); "
                   << "expected " << reply_message_.size();
        reply_message_.clear();
        return false;
      }
      memcpy(message, &(reply_message_[0]), message_length);
      reply_message_.clear();
      return true;
    }

    LOG(ERROR) << "Ignoring operation with I2C flags " << i2c_message->flags;
    return false;
  }

 private:
  // Sent messages, converted to hexadecimal strings, in the order they were
  // transmitted.
  std::vector<std::string> sent_messages_;

  // Message that should be returned in response to read requests.
  // The message will be cleared after the next read request.
  std::vector<uint8_t> reply_message_;

  // True if either writes or reads should report failure.
  bool report_write_failure_ = false;
  bool report_read_failure_ = false;
};

}  // namespace

class ExternalDisplayTest : public TestEnvironment {
 public:
  ExternalDisplayTest()
      : delegate_(new TestDelegate),
        display_(std::unique_ptr<ExternalDisplay::Delegate>(delegate_)),
        test_api_(&display_) {
    request_brightness_message_ =
        // Message header.
        Hex(ExternalDisplay::kDdcHostAddress) +
        Hex(ExternalDisplay::kDdcMessageBodyLengthMask | 2) +
        // Message body.
        Hex(ExternalDisplay::kDdcGetCommand) +
        Hex(ExternalDisplay::kDdcBrightnessIndex) +
        // Checksum byte.
        Hex(ExternalDisplay::kDdcDisplayAddress ^
            ExternalDisplay::kDdcHostAddress ^
            (ExternalDisplay::kDdcMessageBodyLengthMask | 2) ^
            ExternalDisplay::kDdcGetCommand ^
            ExternalDisplay::kDdcBrightnessIndex);
  }
  ~ExternalDisplayTest() override = default;

 protected:
  // Updates the checksum byte that's already present at the end of |message|.
  void UpdateChecksum(uint8_t starting_value, std::vector<uint8_t>* message) {
    uint8_t checksum = starting_value;
    for (size_t i = 0; i < message->size() - 1; ++i)
      checksum ^= (*message)[i];
    (*message)[message->size() - 1] = checksum;
  }

  // Generate a reply to a request to get the brightness, suitable for passing
  // to TestDelegate::set_reply_message().
  std::vector<uint8_t> GetBrightnessReply(uint16_t current_brightness,
                                          uint16_t max_brightness) {
    std::vector<uint8_t> message;
    // Message header.
    message.push_back(ExternalDisplay::kDdcDisplayAddress);
    message.push_back(ExternalDisplay::kDdcMessageBodyLengthMask | 8);
    // Message body.
    message.push_back(ExternalDisplay::kDdcGetReplyCommand);
    message.push_back(0x0);  // Result code.
    message.push_back(ExternalDisplay::kDdcBrightnessIndex);
    message.push_back(0x0);  // VCP type code.
    message.push_back(max_brightness >> 8);
    message.push_back(max_brightness & 0xff);
    message.push_back(current_brightness >> 8);
    message.push_back(current_brightness & 0xff);
    // Checksum byte.
    message.push_back(0x0);
    UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &message);

    return message;
  }

  // Returns the string representation of the message that should be sent to set
  // the brightness to |brightness|.
  std::string GetSetBrightnessMessage(uint16_t brightness) {
    const uint8_t high_byte = brightness >> 8;
    const uint8_t low_byte = brightness & 0xff;
    return
        // Message header.
        Hex(ExternalDisplay::kDdcHostAddress) +
        Hex(ExternalDisplay::kDdcMessageBodyLengthMask | 4) +
        // Message body.
        Hex(ExternalDisplay::kDdcSetCommand) +
        Hex(ExternalDisplay::kDdcBrightnessIndex) + Hex(high_byte) +
        Hex(low_byte) +
        // Checksum byte.
        Hex(ExternalDisplay::kDdcDisplayAddress ^
            ExternalDisplay::kDdcHostAddress ^
            (ExternalDisplay::kDdcMessageBodyLengthMask | 4) ^
            ExternalDisplay::kDdcSetCommand ^
            ExternalDisplay::kDdcBrightnessIndex ^ high_byte ^ low_byte);
  }

  // Pops and returns a string representation of the metric stored in
  // |metrics_sender_|. Crashes if multiple metrics are stored.
  std::string PopMetric() {
    CHECK_LE(metrics_sender_.num_metrics(), 1);
    const std::string metric = metrics_sender_.GetMetric(0);
    metrics_sender_.clear_metrics();
    return metric;
  }

  // What a message requesting the display brightness should look like.
  std::string request_brightness_message_;

  MetricsSenderStub metrics_sender_;

  TestDelegate* delegate_;  // owned elsewhere
  ExternalDisplay display_;
  ExternalDisplay::TestApi test_api_;
};

TEST_F(ExternalDisplayTest, BasicCommunication) {
  // Asking for brightness to be increased by 10% should result in a "get
  // brightness" request being sent.
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            PopMetric());

  // After the timer fires, the reply should be read and a request to set the
  // brightness to 60 should be sent.
  delegate_->set_reply_message(GetBrightnessReply(50, 100));
  EXPECT_EQ(ExternalDisplay::kDdcGetDelay, test_api_.GetTimerDelay());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(60), delegate_->PopSentMessage());

  // The successful read and write should both be reported.
  EXPECT_EQ(2, metrics_sender_.num_metrics());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessReadResultName,
                static_cast<int>(ExternalDisplay::ReceiveResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(0));
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessWriteResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(1));
  metrics_sender_.clear_metrics();

  // Asking for more changes shouldn't result in requests being sent at first,
  // since no time has passed since the previous request. After the timer fires,
  // a new request should be sent containing both adjustments.
  display_.AdjustBrightnessByPercent(20.0);
  EXPECT_EQ("", delegate_->PopSentMessage());
  display_.AdjustBrightnessByPercent(5.0);
  EXPECT_EQ("", delegate_->PopSentMessage());
  EXPECT_EQ(ExternalDisplay::kDdcSetDelay, test_api_.GetTimerDelay());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(85), delegate_->PopSentMessage());

  // The timer should fire again when it's safe to send another message, but
  // nothing should happen since there are no pending adjustments.
  EXPECT_EQ(ExternalDisplay::kDdcSetDelay, test_api_.GetTimerDelay());
  EXPECT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ("", delegate_->PopSentMessage());
  EXPECT_FALSE(test_api_.TriggerTimeout());

  // Let enough time pass for the cached brightness to be invalidated.
  // Asking for another adjustment should result in the brightness being
  // re-read.
  test_api_.AdvanceTime(ExternalDisplay::kCachedBrightnessValid +
                        base::Milliseconds(10));
  display_.AdjustBrightnessByPercent(-10.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());

  // Pretend like the user decreased the brightness via physical buttons on the
  // monitor and reply that the current level is 30.
  delegate_->set_reply_message(GetBrightnessReply(30, 100));
  EXPECT_EQ(ExternalDisplay::kDdcGetDelay, test_api_.GetTimerDelay());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(20), delegate_->PopSentMessage());
}

TEST_F(ExternalDisplayTest, InvalidBrightnessReplies) {
  struct TestCase {
    // Reply message that should be sent from the display.
    std::vector<uint8_t> reply;
    // Metric enum value that should be reported after the failed read.
    ExternalDisplay::ReceiveResult metric;
    // Description of what's being tested.
    std::string description;
  };

  std::vector<TestCase> test_cases;
  std::vector<uint8_t> reply = GetBrightnessReply(50, 100);
  reply[reply.size() - 1] += 1;
  test_cases.push_back(TestCase{reply,
                                ExternalDisplay::ReceiveResult::BAD_CHECKSUM,
                                "incorrect checksum"});

  reply = GetBrightnessReply(50, 100);
  reply[0] += 1;
  UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &reply);
  test_cases.push_back(TestCase{reply,
                                ExternalDisplay::ReceiveResult::BAD_ADDRESS,
                                "incorrect source address"});

  reply = GetBrightnessReply(50, 100);
  reply[1] = ExternalDisplay::kDdcMessageBodyLengthMask | 9;  // Should be 8.
  UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &reply);
  test_cases.push_back(TestCase{reply,
                                ExternalDisplay::ReceiveResult::BAD_LENGTH,
                                "incorrect body length"});

  reply = GetBrightnessReply(50, 100);
  reply[2] = ExternalDisplay::kDdcSetCommand;
  UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &reply);
  test_cases.push_back(TestCase{
      reply, ExternalDisplay::ReceiveResult::BAD_COMMAND, "non-reply command"});

  reply = GetBrightnessReply(50, 100);
  reply[3] = 0x1;  // Should be 0x0 for success.
  UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &reply);
  test_cases.push_back(TestCase{reply,
                                ExternalDisplay::ReceiveResult::BAD_RESULT,
                                "non-zero result code"});

  reply = GetBrightnessReply(50, 100);
  reply[4] = ExternalDisplay::kDdcBrightnessIndex + 1;
  UpdateChecksum(ExternalDisplay::kDdcVirtualHostAddress, &reply);
  test_cases.push_back(TestCase{reply,
                                ExternalDisplay::ReceiveResult::BAD_INDEX,
                                "non-brightness index"});

  // Run through each test case, making sure that no subsequent request is sent
  // after the bogus reply is returned. The timer also shouldn't be rescheduled.
  for (const TestCase& test_case : test_cases) {
    SCOPED_TRACE(test_case.description);

    display_.AdjustBrightnessByPercent(10.0);
    ASSERT_EQ(request_brightness_message_, delegate_->PopSentMessage());
    EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                  metrics::kExternalBrightnessRequestResultName,
                  static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                  metrics::kExternalDisplayResultMax)
                  .ToString(),
              PopMetric());

    delegate_->set_reply_message(test_case.reply);
    ASSERT_TRUE(test_api_.TriggerTimeout());
    EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                  metrics::kExternalBrightnessReadResultName,
                  static_cast<int>(test_case.metric),
                  metrics::kExternalDisplayResultMax)
                  .ToString(),
              PopMetric());

    EXPECT_EQ("", delegate_->PopSentMessage());
    EXPECT_FALSE(test_api_.TriggerTimeout());
  }
}

TEST_F(ExternalDisplayTest, CommunicationFailures) {
  // If the initial brightness request fails, the timer should be stopped.
  delegate_->set_report_write_failure(true);
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_FALSE(test_api_.TriggerTimeout());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::IOCTL_FAILED),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            PopMetric());

  // Now let the initial request succeed but make the read fail. The timer
  // should be stopped.
  delegate_->set_report_write_failure(false);
  delegate_->set_report_read_failure(true);
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_FALSE(test_api_.TriggerTimeout());

  EXPECT_EQ(2, metrics_sender_.num_metrics());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(0));
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessReadResultName,
                static_cast<int>(ExternalDisplay::ReceiveResult::IOCTL_FAILED),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(1));
  metrics_sender_.clear_metrics();

  // Let the initial request and read succeed, but make the attempt to change
  // the brightness fail. The timer should be stopped.
  delegate_->set_report_read_failure(false);
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  delegate_->set_report_write_failure(true);
  delegate_->set_reply_message(GetBrightnessReply(50, 100));
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_FALSE(test_api_.TriggerTimeout());

  EXPECT_EQ(3, metrics_sender_.num_metrics());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(0));
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessReadResultName,
                static_cast<int>(ExternalDisplay::ReceiveResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(1));
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessWriteResultName,
                static_cast<int>(ExternalDisplay::SendResult::IOCTL_FAILED),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(2));
  metrics_sender_.clear_metrics();

  // The previously-read brightness should still be cached, so another
  // adjustment attempt should be attempted immediately. Let it succeed this
  // time.
  delegate_->set_report_write_failure(false);
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_EQ(GetSetBrightnessMessage(60), delegate_->PopSentMessage());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessWriteResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            PopMetric());
}

TEST_F(ExternalDisplayTest, MinimumAndMaximumBrightness) {
  // A request to go below 0 should be capped.
  display_.AdjustBrightnessByPercent(-80.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  delegate_->set_reply_message(GetBrightnessReply(50, 80));
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(0), delegate_->PopSentMessage());

  // Now that the brightness is at 0, a request to decrease it further shouldn't
  // result in a message being sent to the display.
  display_.AdjustBrightnessByPercent(-10.0);
  EXPECT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ("", delegate_->PopSentMessage());

  // Requests above the maximum brightness should also be capped.
  display_.AdjustBrightnessByPercent(120.0);
  EXPECT_EQ(GetSetBrightnessMessage(80), delegate_->PopSentMessage());

  // Trying to increase the brightness further shouldn't do anything.
  display_.AdjustBrightnessByPercent(10.0);
  EXPECT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ("", delegate_->PopSentMessage());

  // Decrease the brightness a bit, and then check that if two adjustments that
  // cancel each other are requested before it's safe to send another request,
  // they cancel each other out and result in nothing being sent to the display.
  display_.AdjustBrightnessByPercent(-10.0);
  EXPECT_EQ(GetSetBrightnessMessage(72), delegate_->PopSentMessage());
  display_.AdjustBrightnessByPercent(-5.0);
  display_.AdjustBrightnessByPercent(5.0);
  EXPECT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ("", delegate_->PopSentMessage());
}

TEST_F(ExternalDisplayTest, Rounding) {
  // 5.3% should be sent to the display as 5/100.
  display_.AdjustBrightnessByPercent(5.3);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  delegate_->set_reply_message(GetBrightnessReply(0, 100));
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(5), delegate_->PopSentMessage());

  // A 4.4% increase goes to 9.7%, which is rounded to 10/100.
  display_.AdjustBrightnessByPercent(4.4);
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(10), delegate_->PopSentMessage());

  // A 0.3% decrease goes to 9.4%, which is rounded to 9/100.
  display_.AdjustBrightnessByPercent(-0.3);
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(9), delegate_->PopSentMessage());

  // A 0.6% decrease goes to 8.8%, which is still rounded to 9 and shouldn't
  // trigger an update.
  display_.AdjustBrightnessByPercent(-0.6);
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ("", delegate_->PopSentMessage());
}

TEST_F(ExternalDisplayTest, ZeroMax) {
  // Make the display return a maximum value of zero.
  display_.AdjustBrightnessByPercent(5.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            PopMetric());

  // ExternalDisplay should report a failure and avoid writing an updated level.
  delegate_->set_reply_message(GetBrightnessReply(0, 0));
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(
      MetricsSenderStub::Metric::CreateEnum(
          metrics::kExternalBrightnessReadResultName,
          static_cast<int>(ExternalDisplay::ReceiveResult::ZERO_MAX_VALUE),
          metrics::kExternalDisplayResultMax)
          .ToString(),
      PopMetric());
  EXPECT_FALSE(test_api_.TriggerTimeout());
}

TEST_F(ExternalDisplayTest, AbsoluteBrightness) {
  // Setting the brightness to 60% should result in a "get brightness" request
  // being sent.
  display_.SetBrightness(60.0);
  EXPECT_EQ(request_brightness_message_, delegate_->PopSentMessage());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessRequestResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            PopMetric());

  // After the timer fires, the reply should be read and a request to set the
  // brightness to 60 should be sent.
  delegate_->set_reply_message(GetBrightnessReply(50, 100));
  EXPECT_EQ(ExternalDisplay::kDdcGetDelay, test_api_.GetTimerDelay());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(60), delegate_->PopSentMessage());

  // The successful read and write should both be reported.
  EXPECT_EQ(2, metrics_sender_.num_metrics());
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessReadResultName,
                static_cast<int>(ExternalDisplay::ReceiveResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(0));
  EXPECT_EQ(MetricsSenderStub::Metric::CreateEnum(
                metrics::kExternalBrightnessWriteResultName,
                static_cast<int>(ExternalDisplay::SendResult::SUCCESS),
                metrics::kExternalDisplayResultMax)
                .ToString(),
            metrics_sender_.GetMetric(1));
  metrics_sender_.clear_metrics();

  // Asking for more changes shouldn't result in requests being sent at first,
  // since no time has passed since the previous request. After the timer fires,
  // a new request should be sent containing the last absolute request combined
  // with the adjustment.
  display_.SetBrightness(50.0);
  EXPECT_EQ("", delegate_->PopSentMessage());
  display_.AdjustBrightnessByPercent(35.0);
  EXPECT_EQ("", delegate_->PopSentMessage());
  EXPECT_EQ(ExternalDisplay::kDdcSetDelay, test_api_.GetTimerDelay());
  ASSERT_TRUE(test_api_.TriggerTimeout());
  EXPECT_EQ(GetSetBrightnessMessage(85), delegate_->PopSentMessage());
}

}  // namespace power_manager::system
