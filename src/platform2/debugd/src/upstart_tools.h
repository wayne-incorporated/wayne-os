// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_UPSTART_TOOLS_H_
#define DEBUGD_SRC_UPSTART_TOOLS_H_

// This tool assists in starting or stopping upstart jobs.

#include <memory>
#include <string>
#include <vector>

#include <brillo/dbus/dbus_method_response.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>

namespace debugd {

class UpstartTools {
 public:
  virtual ~UpstartTools() = default;

  virtual bool IsJobRunning(const std::string& job_name,
                            brillo::ErrorPtr* error) = 0;
  virtual bool RestartJob(const std::string& job_name,
                          brillo::ErrorPtr* error) = 0;
  virtual bool StartJob(const std::string& job_name,
                        brillo::ErrorPtr* error) = 0;
  virtual bool StopJob(const std::string& job_name,
                       brillo::ErrorPtr* error) = 0;
};

class UpstartToolsImpl : public UpstartTools {
 public:
  explicit UpstartToolsImpl(const scoped_refptr<dbus::Bus>& bus);
  ~UpstartToolsImpl() override = default;

  bool IsJobRunning(const std::string& job_name,
                    brillo::ErrorPtr* error) override;
  bool RestartJob(const std::string& job_name,
                  brillo::ErrorPtr* error) override;
  bool StartJob(const std::string& job_name, brillo::ErrorPtr* error) override;
  bool StopJob(const std::string& job_name, brillo::ErrorPtr* error) override;

 private:
  bool CallJobMethod(const std::string& job_name,
                     const std::string& method,
                     const std::vector<std::string>& environment,
                     brillo::ErrorPtr* error);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* upstart_proxy_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_UPSTART_TOOLS_H_
