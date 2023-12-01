// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_ANOMALY_DETECTOR_SERVICE_H_
#define CRASH_REPORTER_ANOMALY_DETECTOR_SERVICE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/timer/timer.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "crash-reporter/anomaly_detector.h"
#include "crash-reporter/anomaly_detector_log_reader.h"

namespace anomaly {

class Service {
 public:
  Service(base::OnceClosure shutdown_callback, bool testonly_send_all);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  bool Init();

 private:
  void ReadLogs();
  void PeriodicUpdate();
  void ProcessVmKernelLog(dbus::MethodCall* method_call,
                          dbus::ExportedObject::ResponseSender sender);

  base::OnceClosure shutdown_callback_;

  scoped_refptr<dbus::Bus> dbus_;
  dbus::ExportedObject* exported_object_;  // Owned by the Bus object

  std::map<std::string, std::unique_ptr<anomaly::Parser>> parsers_;
  std::vector<std::unique_ptr<anomaly::LogReader>> log_readers_;

  std::unique_ptr<anomaly::TerminaParser> termina_parser_;

  base::RepeatingTimer short_timer_;
  base::RepeatingTimer long_timer_;

  base::WeakPtrFactory<Service> weak_ptr_factory_;

  const bool testonly_send_all_;
};

}  // namespace anomaly

#endif  // CRASH_REPORTER_ANOMALY_DETECTOR_SERVICE_H_
