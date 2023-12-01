// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/routines/routine_test_utils.h"

#include <utility>

#include <gtest/gtest.h>

#include "diagnostics/base/mojo_utils.h"

namespace diagnostics {

void VerifyInteractiveUpdate(
    const ash::cros_healthd::mojom::RoutineUpdateUnionPtr& update_union,
    ash::cros_healthd::mojom::DiagnosticRoutineUserMessageEnum
        expected_user_message) {
  ASSERT_FALSE(update_union.is_null());
  ASSERT_TRUE(update_union->is_interactive_update());
  const auto& interactive_update = update_union->get_interactive_update();
  EXPECT_EQ(interactive_update->user_message, expected_user_message);
}

void VerifyNonInteractiveUpdate(
    const ash::cros_healthd::mojom::RoutineUpdateUnionPtr& update_union,
    ash::cros_healthd::mojom::DiagnosticRoutineStatusEnum expected_status,
    const std::string& expected_status_message) {
  ASSERT_FALSE(update_union.is_null());
  ASSERT_TRUE(update_union->is_noninteractive_update());
  const auto& noninteractive_update = update_union->get_noninteractive_update();
  EXPECT_EQ(noninteractive_update->status_message, expected_status_message);
  EXPECT_EQ(noninteractive_update->status, expected_status);
}

std::string GetStringFromValidReadOnlySharedMemoryMapping(
    mojo::ScopedHandle handle) {
  CHECK(handle.is_valid());
  auto shm_mapping =
      GetReadOnlySharedMemoryMappingFromMojoHandle(std::move(handle));
  CHECK(shm_mapping.IsValid());
  return std::string(shm_mapping.GetMemoryAs<const char>(),
                     shm_mapping.mapped_size());
}

}  // namespace diagnostics
