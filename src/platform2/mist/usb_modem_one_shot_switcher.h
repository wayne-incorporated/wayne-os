// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_USB_MODEM_ONE_SHOT_SWITCHER_H_
#define MIST_USB_MODEM_ONE_SHOT_SWITCHER_H_

#include <memory>

namespace mist {

class Context;
class UsbModemSwitchContext;
class UsbModemSwitchOperation;

// A USB modem one-shot switcher, which initiates a modem switch operation for
// a device specified by a UsbModemSwitchContext object. Upon the completion of
// the operation, the message loop is signaled to terminate.
class UsbModemOneShotSwitcher {
 public:
  // Constructs a UsbModemOneShotSwitcher object by taking a raw pointer to a
  // Context object as |context|. The ownership of |context| is not transferred,
  // and thus they should outlive this object.
  explicit UsbModemOneShotSwitcher(Context* context);
  UsbModemOneShotSwitcher(const UsbModemOneShotSwitcher&) = delete;
  UsbModemOneShotSwitcher& operator=(const UsbModemOneShotSwitcher&) = delete;

  ~UsbModemOneShotSwitcher();

  // Initiates a modem switch operation for the device specified by the
  // UsbModemSwitchContext object |switch_context|. Upon the completion of the
  // operation, OnSwitchOperationCompleted() is invoked with the status of the
  // operation. The ownership of |switch_context| is transferred.
  void Start(UsbModemSwitchContext* switch_context);

  bool is_success() const { return is_success_; }

 private:
  // Invoked upon the completion of a switch operation where |success| indicates
  // whether the operation completed successfully or not. |operation| is deleted
  // in this callback.
  void OnSwitchOperationCompleted(UsbModemSwitchOperation* operation,
                                  bool success);

  Context* const context_;
  std::unique_ptr<UsbModemSwitchOperation> operation_;
  bool is_success_;
};

}  // namespace mist

#endif  // MIST_USB_MODEM_ONE_SHOT_SWITCHER_H_
