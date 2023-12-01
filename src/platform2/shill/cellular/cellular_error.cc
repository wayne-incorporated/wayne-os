// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_error.h"

#include <string>

#include <ModemManager/ModemManager.h>

// TODO(armansito): Once we refactor the code to handle the ModemManager D-Bus
// bindings in a dedicated class, this code should move there.
// (See crbug.com/246425)

namespace shill {

namespace {

// TODO(b/217612447): How can we prevent a change in MM from messing up
// the hardcoded strings?
const char kErrorMissingOrUnknownApn[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".MissingOrUnknownApn";

const char kErrorServiceOptionNotSubscribed[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".ServiceOptionNotSubscribed";

const char kErrorUserAuthenticationFailed[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".UserAuthenticationFailed";

const char kErrorIncorrectPassword[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".IncorrectPassword";

const char kErrorIpv4OnlyAllowed[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".Ipv4OnlyAllowed";

const char kErrorIpv6OnlyAllowed[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".Ipv6OnlyAllowed";

const char kErrorSimPin[] = MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".SimPin";

const char kErrorSimPuk[] = MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".SimPuk";

const char kErrorWrongState[] = MM_CORE_ERROR_DBUS_PREFIX ".WrongState";

const char kErrorMobileEquipmentUnknown[] =
    MM_MOBILE_EQUIPMENT_ERROR_DBUS_PREFIX ".Unknown";

}  // namespace

// static
void CellularError::FromMM1ChromeosDBusError(brillo::Error* dbus_error,
                                             Error* error) {
  if (!error)
    return;

  if (!dbus_error) {
    error->Reset();
    return;
  }

  const std::string name = dbus_error->GetCode();
  const std::string msg = dbus_error->GetMessage();
  Error::Type type;

  if (name == kErrorIncorrectPassword)
    type = Error::kIncorrectPin;
  else if (name == kErrorSimPin)
    type = Error::kPinRequired;
  else if (name == kErrorSimPuk)
    type = Error::kPinBlocked;
  else if (name == kErrorMissingOrUnknownApn ||
           name == kErrorServiceOptionNotSubscribed ||
           name == kErrorUserAuthenticationFailed ||
           name == kErrorIpv4OnlyAllowed || name == kErrorIpv6OnlyAllowed)
    type = Error::kInvalidApn;
  else if (name == kErrorMobileEquipmentUnknown)
    type = Error::kInternalError;
  else if (name == kErrorWrongState)
    type = Error::kWrongState;
  else
    type = Error::kOperationFailed;

  if (!msg.empty())
    return error->Populate(type, msg, name);
  else
    return error->Populate(type, "", name);
}
}  // namespace shill
