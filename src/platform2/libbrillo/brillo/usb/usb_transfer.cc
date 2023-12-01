// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_transfer.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include <libusb.h>

namespace brillo {

UsbTransfer::UsbTransfer()
    : transfer_(nullptr), buffer_length_(0), state_(kIdle) {}

UsbTransfer::~UsbTransfer() {
  Free();
}

bool UsbTransfer::Submit(CompletionCallback completion_callback) {
  if (!VerifyAllocated())
    return false;

  if (state_ != kIdle) {
    error_.set_type(UsbError::kErrorTransferAlreadySubmitted);
    return false;
  }

  completion_callback_ = std::move(completion_callback);

  VLOG(1) << "Submit USB transfer: " << *this;
  int result = libusb_submit_transfer(transfer_);
  if (error_.SetFromLibUsbError(static_cast<libusb_error>(result))) {
    state_ = kInProgress;
    return true;
  }
  return false;
}

bool UsbTransfer::Cancel() {
  if (state_ == kIdle) {
    error_.set_type(UsbError::kErrorTransferNotSubmitted);
    return false;
  }

  if (state_ == kCancelling) {
    error_.set_type(UsbError::kErrorTransferBeingCancelled);
    return false;
  }

  int result = libusb_cancel_transfer(transfer_);
  if (error_.SetFromLibUsbError(static_cast<libusb_error>(result))) {
    state_ = kCancelling;
    return true;
  }
  return false;
}

uint8_t UsbTransfer::GetEndpointAddress() const {
  return transfer_ ? transfer_->endpoint : 0;
}

UsbTransferType UsbTransfer::GetType() const {
  if (!transfer_)
    return kUsbTransferTypeUnknown;

  switch (transfer_->type) {
    case LIBUSB_TRANSFER_TYPE_CONTROL:
      return kUsbTransferTypeControl;
    case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
      return kUsbTransferTypeIsochronous;
    case LIBUSB_TRANSFER_TYPE_BULK:
      return kUsbTransferTypeBulk;
    case LIBUSB_TRANSFER_TYPE_INTERRUPT:
      return kUsbTransferTypeInterrupt;
  }
  return kUsbTransferTypeUnknown;
}

UsbTransferStatus UsbTransfer::GetStatus() const {
  if (!transfer_)
    return kUsbTransferStatusUnknown;

  switch (transfer_->status) {
    case LIBUSB_TRANSFER_COMPLETED:
      return kUsbTransferStatusCompleted;
    case LIBUSB_TRANSFER_ERROR:
      return kUsbTransferStatusError;
    case LIBUSB_TRANSFER_TIMED_OUT:
      return kUsbTransferStatusTimedOut;
    case LIBUSB_TRANSFER_CANCELLED:
      return kUsbTransferStatusCancelled;
    case LIBUSB_TRANSFER_STALL:
      return kUsbTransferStatusStall;
    case LIBUSB_TRANSFER_NO_DEVICE:
      return kUsbTransferStatusNoDevice;
    case LIBUSB_TRANSFER_OVERFLOW:
      return kUsbTransferStatusOverflow;
  }
  return kUsbTransferStatusUnknown;
}

int UsbTransfer::GetLength() const {
  return transfer_ ? transfer_->length : 0;
}

int UsbTransfer::GetActualLength() const {
  return transfer_ ? transfer_->actual_length : 0;
}

bool UsbTransfer::IsCompletedWithExpectedLength(int expected_length) const {
  return GetStatus() == kUsbTransferStatusCompleted &&
         GetActualLength() == expected_length;
}

std::string UsbTransfer::ToString() const {
  if (!transfer_)
    return "Transfer (not allocated)";

  return base::StringPrintf(
      "Transfer %p (Type=%s, "
      "Flags=0x%08x, "
      "DeviceHandle=%p, "
      "EndpointAddress=%u, "
      "NumIsoPackets=%d, "
      "Buffer=%p, "
      "Length=%d, "
      "Transferred=%d, "
      "Timeout=%u, "
      "Status=%s)",
      transfer_, UsbTransferTypeToString(GetType()), transfer_->flags,
      transfer_->dev_handle, transfer_->endpoint, transfer_->num_iso_packets,
      transfer_->buffer, transfer_->length, transfer_->actual_length,
      transfer_->timeout, UsbTransferStatusToString(GetStatus()));
}

bool UsbTransfer::VerifyAllocated() {
  if (transfer_)
    return true;

  LOG(ERROR) << "USB transfer is not allocated.";
  error_.set_type(UsbError::kErrorTransferNotAllocated);
  return false;
}

bool UsbTransfer::Allocate(int num_iso_packets) {
  if (transfer_) {
    LOG(ERROR) << "USB transfer already allocated.";
    error_.set_type(UsbError::kErrorTransferAlreadyAllocated);
    return false;
  }

  transfer_ = libusb_alloc_transfer(num_iso_packets);
  if (!transfer_) {
    LOG(ERROR) << "Could not allocate USB transfer.";
    error_.set_type(UsbError::kErrorNoMemory);
    return false;
  }

  VLOG(2) << base::StringPrintf("Allocated USB transfer %p.", transfer_);
  error_.Clear();
  return true;
}

void UsbTransfer::Free() {
  // It is not ok to free a transfer while it is still in progress or being
  // cancelled.
  CHECK_EQ(kIdle, state_);

  if (transfer_) {
    libusb_free_transfer(transfer_);
    VLOG(2) << base::StringPrintf("Freed USB transfer %p.", transfer_);
    transfer_ = nullptr;
  }
}

bool UsbTransfer::AllocateBuffer(int length) {
  if (state_ != kIdle) {
    error_.set_type(UsbError::kErrorTransferAlreadySubmitted);
    return false;
  }

  buffer_.reset(new uint8_t[length]);
  if (buffer_) {
    buffer_length_ = length;
    VLOG(2) << base::StringPrintf(
        "Allocated data buffer %p for USB transfer %p.", buffer_.get(),
        transfer_);
    return true;
  }

  buffer_length_ = 0;
  LOG(ERROR) << base::StringPrintf(
      "Could not allocate data buffer for USB transfer %p.", transfer_);
  error_.set_type(UsbError::kErrorNoMemory);
  return false;
}

void UsbTransfer::OnCompleted(libusb_transfer* transfer) {
  CHECK(transfer);
  UsbTransfer* usb_transfer =
      reinterpret_cast<UsbTransfer*>(transfer->user_data);
  CHECK(usb_transfer);
  CHECK_EQ(transfer, usb_transfer->transfer_);

  VLOG(1) << base::StringPrintf("USB transfer %p completed.", usb_transfer);
  usb_transfer->Complete();
}

void UsbTransfer::Complete() {
  // Change the state to idle before calling the completion callback as this
  // object may be destructed in the completion callback and Free(), which is
  // called in the destructor of this object, expects the state to be idle.
  state_ = kIdle;
  if (!completion_callback_.is_null()) {
    VLOG(2) << base::StringPrintf(
        "Invoke completion callback for USB transfer %p.", transfer_);
    std::move(completion_callback_).Run(this);
  }
}

}  // namespace brillo

std::ostream& operator<<(std::ostream& stream,
                         const brillo::UsbTransfer& transfer) {
  stream << transfer.ToString();
  return stream;
}
