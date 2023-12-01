// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_OBSERVERS_ROUTINE_OBSERVER_H_
#define DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_OBSERVERS_ROUTINE_OBSERVER_H_

#include <base/values.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "diagnostics/mojom/public/cros_healthd_routines.mojom.h"

namespace diagnostics {

// This class subscribes to cros_healthd's audio notifications and outputs
// received notifications to stdout.
class RoutineObserver final : public ash::cros_healthd::mojom::RoutineObserver {
 public:
  explicit RoutineObserver(base::OnceClosure quit_runloop);
  RoutineObserver(const RoutineObserver&) = delete;
  RoutineObserver& operator=(const RoutineObserver&) = delete;
  ~RoutineObserver() override;

  // ash::cros_healthd::mojom::RoutineObserver override.
  void OnRoutineStateChange(
      ash::cros_healthd::mojom::RoutineStatePtr state) override;

  // Helper function to call the receiver's BindNewPipeAndPassRemote for easier
  // calling.
  mojo::PendingRemote<ash::cros_healthd::mojom::RoutineObserver>
  BindNewPipdAndPassRemote() {
    return receiver_.BindNewPipeAndPassRemote();
  }

  // This function will output a base::Value::Dict json object based on the
  // |format_output_callback| given, this function should be set to format the
  // json output. If this callback is not set, by default the json output will
  // be pretty printed into the console.
  void SetFormatOutputCallback(
      base::OnceCallback<void(const base::Value::Dict&)>
          format_output_callback);

 private:
  // This function prints the json object either through
  // |format_output_callback_| if set, or default to printing the JSON with
  // pretty print format.
  void PrintOutput(const base::Value::Dict& output);

  // Print the json object in a customized way.
  base::OnceCallback<void(const base::Value::Dict&)> format_output_callback_;
  // Allows the remote cros_healthd to call RoutineObserver's
  // RoutineObserver methods.
  mojo::Receiver<ash::cros_healthd::mojom::RoutineObserver> receiver_;

  // Run quit_closure_ when it is ready to be destructed.
  base::OnceClosure quit_closure_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTH_TOOL_DIAG_OBSERVERS_ROUTINE_OBSERVER_H_
