// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "spaced/calculator/stateful_free_space_calculator.h"

#include <sys/stat.h>
#include <sys/statvfs.h>

#include <algorithm>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/blkdev_utils/lvm.h>
#include <spaced/proto_bindings/spaced.pb.h>

namespace spaced {
namespace {

constexpr char kStatefulMountPath[] = "/mnt/stateful_partition";

spaced::StatefulDiskSpaceState GetDiskSpaceState(int64_t free_space) {
  if (free_space == -1) {
    return spaced::StatefulDiskSpaceState::NONE;
  } else if (free_space > 2LL * 1024 * 1024 * 1024) {
    return spaced::StatefulDiskSpaceState::NORMAL;
  } else if (free_space > 1LL * 1024 * 1024 * 1024) {
    return spaced::StatefulDiskSpaceState::LOW;
  } else {
    return spaced::StatefulDiskSpaceState::CRITICAL;
  }
}

int64_t GetSignalPeriod(spaced::StatefulDiskSpaceState state) {
  switch (state) {
    case spaced::StatefulDiskSpaceState::LOW:
      return 3;
    case spaced::StatefulDiskSpaceState::CRITICAL:
      return 1;
    default:
      return 5;
  }
}

}  // namespace

StatefulFreeSpaceCalculator::StatefulFreeSpaceCalculator(
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    int64_t time_delta_seconds,
    std::optional<brillo::Thinpool> thinpool,
    base::RepeatingCallback<void(const StatefulDiskSpaceUpdate&)> signal) {
  time_delta_seconds_ = time_delta_seconds;
  timer_.SetTaskRunner(task_runner);
  thinpool_ = thinpool;
  SetSize(-1);
  signal_ = signal;
}

void StatefulFreeSpaceCalculator::Start() {
  timer_.Start(FROM_HERE, base::Seconds(time_delta_seconds_), this,
               &StatefulFreeSpaceCalculator::UpdateSizeAndSignal);
}

void StatefulFreeSpaceCalculator::Stop() {
  timer_.AbandonAndStop();
}

void StatefulFreeSpaceCalculator::UpdateSize() {
  struct statvfs stat;

  if (StatVFS(base::FilePath(kStatefulMountPath), &stat) != 0) {
    PLOG(ERROR) << "Failed to run statvfs() on stateful partition";
    SetSize(-1);
    return;
  }

  int64_t stateful_free_space =
      static_cast<int64_t>(stat.f_bavail) * stat.f_frsize;

  int64_t thinpool_free_space;
  if (thinpool_ && thinpool_->IsValid() &&
      thinpool_->GetFreeSpace(&thinpool_free_space)) {
    // There are two situations here that we need to account for:
    //
    // 1. First boot and post migration to LVM: the majority of the usage
    // resides on the stateful filesystem (and therefore the stateful
    // filesystem's free space is smaller).
    //
    // 2. The likelier scenario is in case there are other logical volumes
    // present; in this case, the amount of writes that can succeed on the
    // stateful filesystem are limited by the space available on the thinpool.
    stateful_free_space = std::min(stateful_free_space, thinpool_free_space);
  }

  SetSize(stateful_free_space);
}

void StatefulFreeSpaceCalculator::UpdateSizeAndSignal() {
  UpdateSize();
  MaybeSignalDiskSpaceUpdate();
}

void StatefulFreeSpaceCalculator::MaybeSignalDiskSpaceUpdate() {
  int64_t stateful_free_space = GetSize();
  base::Time now = base::Time::Now();
  spaced::StatefulDiskSpaceState state = GetDiskSpaceState(stateful_free_space);

  if (now - last_signalled_ > base::Seconds(GetSignalPeriod(state))) {
    spaced::StatefulDiskSpaceUpdate payload;

    payload.set_state(state);
    payload.set_free_space_bytes(stateful_free_space);

    last_signalled_ = now;
    signal_.Run(payload);
  }
}

int StatefulFreeSpaceCalculator::StatVFS(const base::FilePath& path,
                                         struct statvfs* st) {
  return HANDLE_EINTR(statvfs(path.value().c_str(), st));
}

}  // namespace spaced
