// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/ephemeral_profile.h"

#include <base/logging.h>
#include <base/notreached.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/adaptor_interfaces.h"
#include "shill/logging.h"
#include "shill/manager.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kProfile;
static std::string ObjectID(const EphemeralProfile* e) {
  return e->GetRpcIdentifier().value();
}
}  // namespace Logging

namespace {

constexpr char kFriendlyName[] = "(ephemeral)";

}  // namespace

EphemeralProfile::EphemeralProfile(Manager* manager)
    : Profile(manager, Identifier(), base::FilePath(), false) {}

EphemeralProfile::~EphemeralProfile() = default;

std::string EphemeralProfile::GetFriendlyName() const {
  return kFriendlyName;
}

bool EphemeralProfile::AdoptService(const ServiceRefPtr& service) {
  SLOG(this, 2) << "Adding service " << service->log_name()
                << " to ephemeral profile.";
  service->SetProfile(this);
  return true;
}

bool EphemeralProfile::AbandonService(const ServiceRefPtr& service) {
  if (service->profile() == this)
    service->SetProfile(nullptr);
  SLOG(this, 2) << "Removing service " << service->log_name()
                << " from ephemeral profile.";
  return true;
}

bool EphemeralProfile::Save() {
  NOTREACHED();
  return false;
}

}  // namespace shill
