// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/boot_lockbox_service.h"

#include <memory>

#include <sysexits.h>

#include <base/logging.h>
#include <dbus/dbus-protocol.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/bootlockbox/frontend.h>
#include <libhwsec/structures/threading_mode.h>

#include "bootlockbox/hwsec_space.h"
#include "bootlockbox/hwsec_space_impl.h"
#include "bootlockbox/metrics.h"

namespace bootlockbox {

namespace {

void ReportSpaceAvailabilityFromState(Metrics& metrics, SpaceState state) {
  switch (state) {
    case SpaceState::kSpaceNormal:
    case SpaceState::kSpaceUninitialized:
      metrics.ReportSpaceAvailabilityAtStart(SpaceAvailability::kAvailable);
      break;
    case SpaceState::kSpaceWriteLocked:
      metrics.ReportSpaceAvailabilityAtStart(SpaceAvailability::kWriteLocked);
      break;
    case SpaceState::kSpaceNeedPowerwash:
      metrics.ReportSpaceAvailabilityAtStart(SpaceAvailability::kNeedPowerWash);
      break;
    default:
      metrics.ReportSpaceAvailabilityAtStart(SpaceAvailability::kUnknown);
      break;
  }
}

}  // namespace

int BootLockboxService::OnInit() {
  nvspace_utility_ =
      std::make_unique<HwsecSpaceImpl>(hwsec_factory_.GetBootLockboxFrontend());
  boot_lockbox_ = std::make_unique<NVRamBootLockbox>(nvspace_utility_.get());

  if (!boot_lockbox_->Load() &&
      boot_lockbox_->GetState() == SpaceState::kSpaceUndefined) {
    LOG(INFO) << "Space is not defined, define it now";

    // Register the ownership callback before defining the space could prevent
    // the race condition.
    if (!boot_lockbox_->RegisterOwnershipCallback()) {
      LOG(ERROR) << "Failed to register ownership callback";
    }

    if (!boot_lockbox_->DefineSpace()) {
      // TPM define nvspace failed but continue to run the service so
      // bootlockbox client can still communicated with bootlockbox. The client
      // need this to differentiate boot lockbox service errors and tpm errors.
      LOG(ERROR) << "Failed to create nvspace";
    }
  }

  ReportSpaceAvailabilityFromState(*metrics_, boot_lockbox_->GetState());

  // Publish the service to dbus. Note that if nvspace is not defined,
  // calls to the interface would receive failure messages.
  const int return_code = brillo::DBusServiceDaemon::OnInit();
  if (return_code != EX_OK) {
    LOG(ERROR) << "Failed to start bootlockbox service";
    return return_code;
  }
  LOG(INFO) << "BootLockboxd started";
  return EX_OK;
}

void BootLockboxService::OnShutdown(int* exit_code) {
  VLOG(1) << "Shutting down bootlockbox service";
  brillo::DBusServiceDaemon::OnShutdown(exit_code);
}

void BootLockboxService::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  VLOG(1) << "Register dbus objects...";
  boot_lockbox_dbus_adaptor_.reset(
      new BootLockboxDBusAdaptor(bus_, boot_lockbox_.get()));
  boot_lockbox_dbus_adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
  VLOG(1) << "Register dbus object complete";
}

BootLockboxService::BootLockboxService()
    : brillo::DBusServiceDaemon("org.chromium.BootLockbox"),
      hwsec_factory_(hwsec::ThreadingMode::kCurrentThread),
      metrics_(std::make_unique<Metrics>()) {}

BootLockboxService::~BootLockboxService() {}

}  // namespace bootlockbox
