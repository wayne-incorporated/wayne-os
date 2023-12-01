// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_RPC_TASK_H_
#define SHILL_RPC_TASK_H_

#include <map>
#include <memory>
#include <string>

#include "shill/data_types.h"

namespace shill {

// Declared in the header to avoid linking unused code into shims.
static const char kRpcTaskServiceVariable[] = "SHILL_TASK_SERVICE";
static const char kRpcTaskPathVariable[] = "SHILL_TASK_PATH";

class ControlInterface;
class RpcTaskAdaptorInterface;

class RpcTaskDelegate {
 public:
  virtual ~RpcTaskDelegate() = default;

  virtual void GetLogin(std::string* user, std::string* password) = 0;
  virtual void Notify(const std::string& reason,
                      const std::map<std::string, std::string>& dict) = 0;
};

// RPC tasks are currently used by VPN drivers for communication with external
// VPN processes. The RPC task should be owned by a single owner -- its
// RpcTaskDelegate -- so no need to be reference counted.
class RpcTask {
 public:
  // A constructor for the RpcTask object.
  RpcTask(ControlInterface* control_interface, RpcTaskDelegate* delegate);
  RpcTask(const RpcTask&) = delete;
  RpcTask& operator=(const RpcTask&) = delete;

  virtual ~RpcTask();

  virtual void GetLogin(std::string* user, std::string* password) const;
  virtual void Notify(const std::string& reason,
                      const std::map<std::string, std::string>& dict);

  // Returns a string that is guaranteed to uniquely identify this RpcTask
  // instance.
  const std::string& UniqueName() const { return unique_name_; }

  // Generates environment variable strings for a child process to
  // communicate back to us over RPC.
  virtual std::map<std::string, std::string> GetEnvironment() const;
  const RpcIdentifier& GetRpcIdentifier() const;
  const RpcIdentifier& GetRpcConnectionIdentifier() const;

 private:
  RpcTaskDelegate* delegate_;
  static unsigned int serial_number_;
  std::string unique_name_;  // MUST be unique amongst RPC task instances
  std::unique_ptr<RpcTaskAdaptorInterface> adaptor_;
};

}  // namespace shill

#endif  // SHILL_RPC_TASK_H_
