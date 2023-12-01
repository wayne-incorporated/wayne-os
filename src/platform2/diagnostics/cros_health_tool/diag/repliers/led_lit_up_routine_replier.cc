// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/diag/repliers/led_lit_up_routine_replier.h"

#include <utility>

#include <base/functional/bind.h>

namespace diagnostics {

LedLitUpRoutineReplier::LedLitUpRoutineReplier(
    mojo::PendingReceiver<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
        receiver)
    : receiver_{this /* impl */, std::move(receiver)},
      get_color_matched_handler_(
          base::BindRepeating([](GetColorMatchedCallback callback) {
            LOG(WARNING) << "GetColorMatchedHandler not set";
          })) {
  DCHECK(receiver_.is_bound());
}

void LedLitUpRoutineReplier::GetColorMatched(GetColorMatchedCallback callback) {
  get_color_matched_handler_.Run(std::move(callback));
}

void LedLitUpRoutineReplier::SetGetColorMatchedHandler(
    const base::RepeatingCallback<void(GetColorMatchedCallback)>& handler) {
  get_color_matched_handler_ = std::move(handler);
}

}  // namespace diagnostics
