// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_ROUTINES_LED_LIT_UP_LED_LIT_UP_H_
#define DIAGNOSTICS_CROS_HEALTHD_ROUTINES_LED_LIT_UP_LED_LIT_UP_H_

#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>

#include "diagnostics/cros_healthd/routines/diag_routine_with_status.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_diagnostics.mojom.h"

namespace diagnostics {

class LedLitUpRoutine final : public DiagnosticRoutineWithStatus {
 public:
  explicit LedLitUpRoutine(
      Context* context,
      ash::cros_healthd::mojom::LedName name,
      ash::cros_healthd::mojom::LedColor color,
      mojo::PendingRemote<ash::cros_healthd::mojom::LedLitUpRoutineReplier>
          replier);
  LedLitUpRoutine(const LedLitUpRoutine&) = delete;
  LedLitUpRoutine& operator=(const LedLitUpRoutine&) = delete;

  // DiagnosticRoutine overrides:
  ~LedLitUpRoutine() override;
  void Start() override;
  void Resume() override;
  void Cancel() override;
  void PopulateStatusUpdate(ash::cros_healthd::mojom::RoutineUpdate* response,
                            bool include_output) override;

 private:
  void RunNextStep();
  void ReplierDisconnectHandler();
  void SetLedColorCallback(const std::optional<std::string>& err);
  void GetColorMatchedCallback(bool matched);
  void ResetLedColorCallback(const std::optional<std::string>& err);

  // Context object used to communicate with the executor.
  Context* context_;

  // The target LED.
  ash::cros_healthd::mojom::LedName name_;
  // The target color.
  ash::cros_healthd::mojom::LedColor color_;
  // A replier that can answer whether the actual LED color matches the
  // expected color.
  mojo::Remote<ash::cros_healthd::mojom::LedLitUpRoutineReplier> replier_;

  enum TestStep {
    kInitialize = 0,
    kSetColor = 1,
    kGetColorMatched = 2,
    kResetColor = 3,
    kComplete = 4,  // Should be the last one. New step should be added before
                    // it.
  };
  TestStep step_;

  // The response of |GetColorMatched| from |replier_|.
  bool color_matched_response_ = false;

  // Must be the last class member.
  base::WeakPtrFactory<LedLitUpRoutine> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_ROUTINES_LED_LIT_UP_LED_LIT_UP_H_
