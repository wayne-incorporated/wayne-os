// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_TRANSFER_H_
#define LIBBRILLO_BRILLO_USB_USB_TRANSFER_H_

#include <stdint.h>

#include <memory>
#include <ostream>  // NOLINT(readability/streams)
#include <string>

#include <base/functional/callback.h>
#include <brillo/brillo_export.h>
#include <gtest/gtest_prod.h>

#include "brillo/usb/usb_constants.h"
#include "brillo/usb/usb_error.h"

struct libusb_transfer;

namespace brillo {

// A base class encapsulating a USB transfer, which wraps a libusb_transfer C
// struct from libusb 1.0 into a C++ object. This class does not implement a
// specific type of transfer, so it cannot be instantiated and must be extended
// for each type of transfer. In particular, a derived class should set up the
// wrapped libusb_transfer accordingly for a specific type of transfer.
class BRILLO_EXPORT UsbTransfer {
 public:
  using CompletionCallback = base::OnceCallback<void(UsbTransfer* transfer)>;

  enum State { kIdle, kInProgress, kCancelling };

  ~UsbTransfer();

  // Submits this USB transfer, which will happen asynchronously. Returns true
  // on success. If the underlying libusb_transfer struct is not allocated, sets
  // |error_| to UsbError::kErrorTransferNotAllocated and returns false. If this
  // transfer has been submitted and is still in progress, sets |error_| to
  // UsbError::kErrorTransferAlreadySubmitted and returns false. Upon the
  // completion of this transfer, |completion_callback| is invoked. It is ok to
  // submit this transfer again after completion.
  bool Submit(CompletionCallback completion_callback);

  // Cancels this USB transfer if it has been submitted via Submit(). Returns
  // true on success. If this transfer has not been submitted, sets |error_| to
  // UsbError::kErrorTransferNotSubmitted and returns false. If a previous
  // cancellation is already in progress, sets |error_| to
  // UsbError::kErrorTransferBeingCancelled and returns false. The cancellation
  // may not have completed when this method returns. Once this transfer is
  // completely cancelled, |completion_callback_| is invoked.
  bool Cancel();

  // Getters for retrieving fields of the libusb_transfer struct.
  uint8_t GetEndpointAddress() const;
  UsbTransferType GetType() const;
  UsbTransferStatus GetStatus() const;
  int GetLength() const;
  int GetActualLength() const;

  // Returns true if this tranfer is completed with the expected length, i.e.
  // GetStatus() returns kUsbTransferStatusCompleted and GetActualLength()
  // returns |expected_length|.
  bool IsCompletedWithExpectedLength(int expected_length) const;

  // Returns a string describing the properties of this object for logging
  // purpose.
  std::string ToString() const;

  uint8_t* buffer() { return buffer_.get(); }
  int buffer_length() const { return buffer_length_; }
  State state() const { return state_; }
  const UsbError& error() const { return error_; }

 protected:
  UsbTransfer();
  UsbTransfer(const UsbTransfer&) = delete;
  UsbTransfer& operator=(const UsbTransfer&) = delete;

  // Verifies that the underlying libusb_transfer struct is allocated,
  // and if so, returns true. Otherwise, set |error_| to
  // UsbError::kErrorTransferNotAllocated and returns false.
  bool VerifyAllocated();

  // Allocates the underlying libusb_transfer struct with |num_iso_packets|
  // isochronous packet descriptors. Returns true on success.
  bool Allocate(int num_iso_packets);

  // Frees the underlying libusb_transfer struct.
  void Free();

  // Allocates the transfer buffer to hold |length| bytes of data. Return true
  // on success.
  bool AllocateBuffer(int length);

  // Called by libusb upon the completion of the underlying USB transfer.
  // A derived class associates this callback to the underlying libusb_transfer
  // struct when setting the transfer.
  static void OnCompleted(libusb_transfer* transfer);

  // Completes the transfer by invoking the completion callback.
  void Complete();

  libusb_transfer* transfer() const { return transfer_; }
  UsbError* mutable_error() { return &error_; }

 private:
  friend class UsbTransferTest;
  FRIEND_TEST(UsbTransferTest, AllocateAfterAllocate);
  FRIEND_TEST(UsbTransferTest, AllocateBuffer);
  FRIEND_TEST(UsbTransferTest, AllocateBufferAfterSubmit);
  FRIEND_TEST(UsbTransferTest, FreeBeforeAllocate);
  FRIEND_TEST(UsbTransferTest, GetType);
  FRIEND_TEST(UsbTransferTest, VerifyAllocated);

  libusb_transfer* transfer_;
  std::unique_ptr<uint8_t[]> buffer_;
  int buffer_length_;
  State state_;
  CompletionCallback completion_callback_;
  UsbError error_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const brillo::UsbTransfer& transfer);

#endif  // LIBBRILLO_BRILLO_USB_USB_TRANSFER_H_
