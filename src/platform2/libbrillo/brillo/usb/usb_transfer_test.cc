// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_transfer.h"

#include <libusb.h>

#include <iterator>

#include <gtest/gtest.h>

namespace brillo {

class UsbTransferTest : public testing::Test {
 protected:
  UsbTransferTest() : original_transfer_state_(UsbTransfer::kIdle) {}

  void TearDown() override {
    // Take out the injected libusb_transfer to bypass the invocation of
    // libusb_free_transfer() in UsbTransfer.
    if (transfer_.transfer_ == &test_transfer_)
      transfer_.transfer_ = nullptr;

    transfer_.state_ = original_transfer_state_;
  }

  // Temporarily injects a hand crafted libusb_transfer struct into |transfer_|
  // for testing. The injected libusb_transfer struct is removed in TearDown().
  void InjectTestLibUsbTransfer() { transfer_.transfer_ = &test_transfer_; }

  // Pretends the transfer has been submitted and is still in progress.
  void PretendTransferInProgress() {
    original_transfer_state_ = transfer_.state_;
    transfer_.state_ = UsbTransfer::kInProgress;
  }

  // Pretends the transfer is being cancelled.
  void PretendTransferBeingCancelled() {
    original_transfer_state_ = transfer_.state_;
    transfer_.state_ = UsbTransfer::kCancelling;
  }

  UsbTransfer transfer_;
  UsbTransfer::State original_transfer_state_;
  libusb_transfer test_transfer_;
};

TEST_F(UsbTransferTest, DefaultConstructor) {
  EXPECT_EQ(nullptr, transfer_.buffer());
  EXPECT_EQ(0, transfer_.buffer_length());
  EXPECT_EQ(UsbTransfer::kIdle, transfer_.state());
  EXPECT_TRUE(transfer_.error().IsSuccess());
}

TEST_F(UsbTransferTest, GetType) {
  EXPECT_EQ(kUsbTransferTypeUnknown, transfer_.GetType());

  InjectTestLibUsbTransfer();

  test_transfer_.type = LIBUSB_TRANSFER_TYPE_CONTROL;
  EXPECT_EQ(kUsbTransferTypeControl, transfer_.GetType());

  test_transfer_.type = LIBUSB_TRANSFER_TYPE_ISOCHRONOUS;
  EXPECT_EQ(kUsbTransferTypeIsochronous, transfer_.GetType());

  test_transfer_.type = LIBUSB_TRANSFER_TYPE_BULK;
  EXPECT_EQ(kUsbTransferTypeBulk, transfer_.GetType());

  test_transfer_.type = LIBUSB_TRANSFER_TYPE_INTERRUPT;
  EXPECT_EQ(kUsbTransferTypeInterrupt, transfer_.GetType());
}

TEST_F(UsbTransferTest, GetStatus) {
  EXPECT_EQ(kUsbTransferStatusUnknown, transfer_.GetStatus());

  InjectTestLibUsbTransfer();

  test_transfer_.status = LIBUSB_TRANSFER_COMPLETED;
  EXPECT_EQ(kUsbTransferStatusCompleted, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_ERROR;
  EXPECT_EQ(kUsbTransferStatusError, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_TIMED_OUT;
  EXPECT_EQ(kUsbTransferStatusTimedOut, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_CANCELLED;
  EXPECT_EQ(kUsbTransferStatusCancelled, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_STALL;
  EXPECT_EQ(kUsbTransferStatusStall, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_NO_DEVICE;
  EXPECT_EQ(kUsbTransferStatusNoDevice, transfer_.GetStatus());

  test_transfer_.status = LIBUSB_TRANSFER_OVERFLOW;
  EXPECT_EQ(kUsbTransferStatusOverflow, transfer_.GetStatus());
}

TEST_F(UsbTransferTest, GetLength) {
  EXPECT_EQ(0, transfer_.GetLength());

  InjectTestLibUsbTransfer();

  test_transfer_.length = 20;
  EXPECT_EQ(test_transfer_.length, transfer_.GetLength());
}

TEST_F(UsbTransferTest, GetActualLength) {
  EXPECT_EQ(0, transfer_.GetLength());

  InjectTestLibUsbTransfer();

  test_transfer_.actual_length = 10;
  EXPECT_EQ(test_transfer_.actual_length, transfer_.GetActualLength());
}

TEST_F(UsbTransferTest, IsCompletedWithExpectedLength) {
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(0));

  InjectTestLibUsbTransfer();

  test_transfer_.actual_length = 5;
  test_transfer_.status = LIBUSB_TRANSFER_COMPLETED;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.actual_length = 10;
  EXPECT_TRUE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_ERROR;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_TIMED_OUT;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_CANCELLED;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_STALL;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_NO_DEVICE;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));

  test_transfer_.status = LIBUSB_TRANSFER_OVERFLOW;
  EXPECT_FALSE(transfer_.IsCompletedWithExpectedLength(10));
}

TEST_F(UsbTransferTest, VerifyAllocated) {
  EXPECT_FALSE(transfer_.VerifyAllocated());
  EXPECT_EQ(UsbError::kErrorTransferNotAllocated, transfer_.error().type());
}

TEST_F(UsbTransferTest, AllocateAfterAllocate) {
  InjectTestLibUsbTransfer();
  EXPECT_FALSE(transfer_.Allocate(0));
  EXPECT_EQ(UsbError::kErrorTransferAlreadyAllocated, transfer_.error().type());
}

TEST_F(UsbTransferTest, FreeBeforeAllocate) {
  // Free() without calling Allocate() should be ok.
  transfer_.Free();
}

TEST_F(UsbTransferTest, AllocateBuffer) {
  // Allocate a zero-size buffer should be ok.
  EXPECT_TRUE(transfer_.AllocateBuffer(0));
  EXPECT_NE(nullptr, transfer_.buffer());
  EXPECT_EQ(0, transfer_.buffer_length());

  // Re-allocate the buffer should be ok.
  const uint8_t kTestData[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  EXPECT_TRUE(transfer_.AllocateBuffer(std::size(kTestData)));
  EXPECT_NE(nullptr, transfer_.buffer());
  EXPECT_EQ(std::size(kTestData), transfer_.buffer_length());
  // Write to the allocated buffer and then read from it to ensure the buffer
  // is properly allocated.
  memcpy(transfer_.buffer(), kTestData, std::size(kTestData));
  EXPECT_EQ(0, memcmp(transfer_.buffer(), kTestData, std::size(kTestData)));
}

TEST_F(UsbTransferTest, AllocateBufferAfterSubmit) {
  PretendTransferInProgress();
  EXPECT_FALSE(transfer_.AllocateBuffer(0));
  EXPECT_EQ(UsbTransfer::kInProgress, transfer_.state());
  EXPECT_EQ(UsbError::kErrorTransferAlreadySubmitted, transfer_.error().type());
}

TEST_F(UsbTransferTest, SubmitBeforeAllocate) {
  EXPECT_FALSE(transfer_.Submit(UsbTransfer::CompletionCallback()));
  EXPECT_EQ(UsbTransfer::kIdle, transfer_.state());
  EXPECT_EQ(UsbError::kErrorTransferNotAllocated, transfer_.error().type());
}

TEST_F(UsbTransferTest, SubmitBeforeComplete) {
  InjectTestLibUsbTransfer();
  PretendTransferInProgress();
  EXPECT_FALSE(transfer_.Submit(UsbTransfer::CompletionCallback()));
  EXPECT_EQ(UsbTransfer::kInProgress, transfer_.state());
  EXPECT_EQ(UsbError::kErrorTransferAlreadySubmitted, transfer_.error().type());
}

TEST_F(UsbTransferTest, CancelBeforeSubmit) {
  EXPECT_FALSE(transfer_.Cancel());
  EXPECT_EQ(UsbTransfer::kIdle, transfer_.state());
  EXPECT_EQ(UsbError::kErrorTransferNotSubmitted, transfer_.error().type());
}

TEST_F(UsbTransferTest, CancelWhileBeingCancelled) {
  PretendTransferBeingCancelled();
  EXPECT_FALSE(transfer_.Cancel());
  EXPECT_EQ(UsbTransfer::kCancelling, transfer_.state());
  EXPECT_EQ(UsbError::kErrorTransferBeingCancelled, transfer_.error().type());
}

}  // namespace brillo
