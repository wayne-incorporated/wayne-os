// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_REPLIERS_LED_LIT_UP_ROUTINE_REPLIER_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_REPLIERS_LED_LIT_UP_ROUTINE_REPLIER_H_

#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

#include <optional>

#include <base/functional/callback.h>
#include <mojo/public/cpp/bindings/receiver.h>

namespace diagnostics {

class LedLitUpRoutineReplier
    : public ash::cros_healthd::mojom::LedLitUpRoutineReplier {
 public:
  explicit LedLitUpRoutineReplier(
      mojo::PendingReceiver<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          receiver);
  LedLitUpRoutineReplier(const LedLitUpRoutineReplier&) = delete;
  LedLitUpRoutineReplier& operator=(const LedLitUpRoutineReplier&) = delete;

  // ash::cros_healthd::mojom::LedLitUpRoutineReplier overrides:
  void GetColorMatched(GetColorMatchedCallback callback);

  void SetGetColorMatchedHandler(
      const base::RepeatingCallback<void(GetColorMatchedCallback)>& handler);

 private:
  mojo::Receiver<ash::cros_healthd::mojom::LedLitUpRoutineReplier> receiver_;
  base::RepeatingCallback<void(GetColorMatchedCallback)>
      get_color_matched_handler_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_REPLIERS_LED_LIT_UP_ROUTINE_REPLIER_H_
