// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_MOJO_UTILS_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_MOJO_UTILS_H_

#include <base/memory/read_only_shared_memory_region.h>
#include <base/strings/string_piece.h>
#include <mojo/public/cpp/system/handle.h>

namespace diagnostics {
namespace wilco {

// Allows to get access to the buffer in read only shared memory. It converts
// mojo::Handle to base::ReadOnlySharedMemoryRegion.
//
// |handle| must be a valid mojo handle of the non-empty buffer in the shared
// memory.
//
// Returns invalid |base::ReadOnlySharedMemoryMapping| if error.
base::ReadOnlySharedMemoryMapping GetReadOnlySharedMemoryMappingFromMojoHandle(
    mojo::ScopedHandle handle);

// Allocates buffer in shared memory, copies |content| to the buffer and
// converts shared buffer handle into |mojo::ScopedHandle|.
//
// Allocated shared memory is read only for another process.
//
// Returns invalid |mojo::ScopedHandle| if error happened or |content| is empty.
mojo::ScopedHandle CreateReadOnlySharedMemoryRegionMojoHandle(
    base::StringPiece content);

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_MOJO_UTILS_H_
