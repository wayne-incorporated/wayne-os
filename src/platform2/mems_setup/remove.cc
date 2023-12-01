// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include <base/task/single_thread_task_executor.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <iioservice/include/dbus-constants.h>
#include <libmems/iio_context_impl.h>

int main(int argc, char** argv) {
  DEFINE_int32(device_id, -1,
               "The IIO device id for the sensor being "
               "initialized, such as iio:device0.");

  brillo::OpenLog("mems_remove", true /*log_pid*/);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  brillo::FlagHelper::Init(argc, argv, "Chromium OS MEMS Remove");

  if (FLAGS_device_id == -1) {
    LOG(ERROR) << "mems_remove must be called with device id";
    exit(1);
  }

  LOG(INFO) << "Starting mems_remove [id=" << FLAGS_device_id << "]";

  std::unique_ptr<libmems::IioContext> context(new libmems::IioContextImpl());
  if (context->IsValid() && context->GetDeviceById(FLAGS_device_id)) {
    LOG(ERROR) << "Device with id: " << FLAGS_device_id << " still exists";
    return 1;
  }

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  if (!bus->Connect()) {
    LOG(ERROR) << "mems_remove: Cannot connect to D-Bus.";
    return 1;
  }

  dbus::ObjectProxy* proxy = bus->GetObjectProxy(
      ::iioservice::kIioserviceServiceName,
      dbus::ObjectPath(::iioservice::kIioserviceServicePath));

  dbus::MethodCall method_call(::iioservice::kIioserviceInterface,
                               ::iioservice::kMemsRemoveDoneMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendInt32(FLAGS_device_id);

  proxy->CallMethodAndBlock(&method_call,
                            dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  return 0;
}
