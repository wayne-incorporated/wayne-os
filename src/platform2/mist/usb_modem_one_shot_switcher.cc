// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/usb_modem_one_shot_switcher.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>

#include "mist/context.h"
#include "mist/event_dispatcher.h"
#include "mist/metrics.h"
#include "mist/usb_modem_switch_context.h"
#include "mist/usb_modem_switch_operation.h"

namespace mist {

// TODO(benchan): Add unit tests for UsbModemOneShotSwitcher.

UsbModemOneShotSwitcher::UsbModemOneShotSwitcher(Context* context)
    : context_(context), is_success_(false) {
  CHECK(context_);
}

UsbModemOneShotSwitcher::~UsbModemOneShotSwitcher() {
  if (operation_) {
    operation_->Cancel();
    operation_.reset();
  }
}

void UsbModemOneShotSwitcher::Start(UsbModemSwitchContext* switch_context) {
  // Ownership of |switch_context| is transferred to |operation_|.
  operation_.reset(new UsbModemSwitchOperation(context_, switch_context));
  CHECK(operation_);

  operation_->Start(
      base::BindOnce(&UsbModemOneShotSwitcher::OnSwitchOperationCompleted,
                     base::Unretained(this)));
}

void UsbModemOneShotSwitcher::OnSwitchOperationCompleted(
    UsbModemSwitchOperation* operation, bool success) {
  CHECK_EQ(operation_.get(), operation);
  operation_.reset();

  is_success_ = success;
  context_->metrics()->RecordSwitchResult(success);

  // Stop the message loop upon the completion of the switch operation.
  context_->event_dispatcher()->Stop();
}

}  // namespace mist
