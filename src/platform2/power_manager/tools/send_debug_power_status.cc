// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/run_loop.h>
#include <base/strings/string_split.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <google/protobuf/message_lite.h>

#include "power_manager/proto_bindings/power_supply_properties.pb.h"

namespace power_manager {

void EmitSignal(const PowerSupplyProperties& proto) {
  dbus::Signal signal(kPowerManagerInterface, kPowerSupplyPollSignal);
  dbus::MessageWriter writer(&signal);
  writer.AppendProtoAsArrayOfBytes(proto);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  CHECK(bus->RequestOwnershipAndBlock(kPowerManagerServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY))
      << "Unable to take ownership of " << kPowerManagerServiceName;

  dbus::ExportedObject* object =
      bus->GetExportedObject(dbus::ObjectPath(kPowerManagerServicePath));
  CHECK(object);
  object->SendSignal(&signal);
}

}  // namespace power_manager

int main(int argc, char* argv[]) {
  DEFINE_double(battery_percent, 100.0, "Current battery charge in [0, 100]");
  DEFINE_int32(battery_state, 2, "BatteryState enum value");
  DEFINE_int32(battery_time_to_empty, -1, "Seconds until battery is empty");
  DEFINE_int32(battery_time_to_full, -1, "Seconds until battery is full");
  DEFINE_bool(calculating_battery_time, false,
              "True if battery time estimates "
              "are still being calculated");
  DEFINE_int32(external_power, 2, "ExternalPower enum value");
  DEFINE_string(power_source_id, "", "ID of the active power source");
  DEFINE_string(power_sources, "",
                "Comma-separated list of "
                "id:manufacturer:model:active_by_default values describing "
                "available external power sources; active_by_default is 1 if "
                "true");

  brillo::FlagHelper::Init(
      argc, argv,
      "Emits a fake D-Bus signal describing the current power supply status.\n"
      "Run this as the \"power\" user after stopping powerd.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  power_manager::PowerSupplyProperties proto;
  proto.set_battery_percent(FLAGS_battery_percent);
  proto.set_battery_state(
      static_cast<power_manager::PowerSupplyProperties_BatteryState>(
          FLAGS_battery_state));
  proto.set_battery_time_to_empty_sec(FLAGS_battery_time_to_empty);
  proto.set_battery_time_to_full_sec(FLAGS_battery_time_to_full);
  proto.set_is_calculating_battery_time(FLAGS_calculating_battery_time);
  proto.set_external_power(
      static_cast<power_manager::PowerSupplyProperties_ExternalPower>(
          FLAGS_external_power));
  proto.set_external_power_source_id(FLAGS_power_source_id);

  std::vector<std::string> sources = base::SplitString(
      FLAGS_power_sources, ",", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
  for (auto source : sources) {
    std::vector<std::string> parts = base::SplitString(
        source, ":", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    CHECK_EQ(parts.size(), 4u) << "Expected "
                               << "id:manufacturer:model:active_by_default but "
                               << "got \"" << source << "\"";
    power_manager::PowerSupplyProperties_PowerSource* proto_source =
        proto.add_available_external_power_source();
    proto_source->set_id(parts[0]);
    proto_source->set_manufacturer_id(parts[1]);
    proto_source->set_model_id(parts[2]);
    proto_source->set_active_by_default(parts[3] == "1");
  }

  EmitSignal(proto);
  base::RunLoop().RunUntilIdle();
  return 0;
}
