// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_THROTTLER_H_
#define SHILL_THROTTLER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>

#include "shill/callbacks.h"
#include "shill/file_io.h"
#include "shill/manager.h"
#include "shill/net/io_handler.h"
#include "shill/net/process_manager.h"

namespace shill {

class IOHandlerFactory;

// The Throttler class implements bandwidth throttling for inbound/outbound
// traffic, using Linux's 'traffic control'(tc) tool from the iproute2 code.
// (https://wiki.linuxfoundation.org/networking/iproute2).
// A detailed introduction to traffic control using tc is available at
// http://lartc.org/howto/
// This solution makes use of two queueing disciplines ('qdisc's),
// one each for ingress (inbound) and egress (outbound) traffic and
// a policing filter on the ingress side.
// Any inbound traffic above a rate of ${DLRATE} kbits/s is dropped on the
// floor. For egress (upload) traffic, a qdisc using the Hierarchical Token
// Bucket algorithm is used.
// The implementation spawns the 'tc' process in a minijail and writes
// commands to its stdin.

class Throttler {
 public:
  Throttler(EventDispatcher* dispatcher, Manager* manager);
  Throttler(const Throttler&) = delete;
  Throttler& operator=(const Throttler&) = delete;

  virtual ~Throttler();

  virtual bool DisableThrottlingOnAllInterfaces(ResultCallback callback);
  virtual bool ThrottleInterfaces(ResultCallback callback,
                                  uint32_t upload_rate_kbits,
                                  uint32_t download_rate_kbits);

  virtual bool ApplyThrottleToNewInterface(const std::string& interface_name);

 private:
  static const char kTCPath[];
  static const char* const kTCCleanUpCmds[];
  static const char* const kTCThrottleUplinkCmds[];
  static const char* const kTCThrottleDownlinkCmds[];

  static const char kTCUser[];
  static const char kTCGroup[];

  friend class ThrottlerTest;

  FRIEND_TEST(ThrottlerTest, ThrottleCallsTCExpectedTimesAndSetsState);
  FRIEND_TEST(ThrottlerTest, NewlyAddedInterfaceIsThrottled);
  FRIEND_TEST(ThrottlerTest, DisablingThrottleClearsState);
  FRIEND_TEST(ThrottlerTest, DisablingThrottleWhenNoThrottleExists);

  // Required for spawning the 'tc' process
  // and communicating with it.
  FileIO* file_io_;
  int tc_stdin_;

  std::unique_ptr<IOHandler> tc_stdin_handler_;

  // Statekeeping while spawning 'tc'
  pid_t tc_pid_;
  std::vector<std::string> tc_commands_;
  ResultCallback callback_;

  // Applicable when throttling is called for multiple
  // interfaces (i.e. ThrottleInterfaces)
  std::vector<std::string> tc_interfaces_to_throttle_;
  std::string tc_current_interface_;

  // Throttling status-keeping
  bool desired_throttling_enabled_;
  uint32_t desired_upload_rate_kbits_;
  uint32_t desired_download_rate_kbits_;

  virtual bool StartTCForCommands(const std::vector<std::string>& commands);

  virtual bool Throttle(ResultCallback callback,
                        const std::string& interface_name,
                        uint32_t upload_rate_kbits,
                        uint32_t download_rate_kbits);

  // Used to write to 'tc''s stdin
  virtual void WriteTCCommands(int fd);

  // Called when the tc command is processed.
  virtual void OnProcessExited(int exit_status);

  // Helpers
  virtual void Done(ResultCallback callback,
                    Error::Type error_type,
                    const std::string& message);

  virtual std::string GetNextInterface();

  virtual void ClearTCState();
  virtual void ClearThrottleStatus();

  // To get a list of interfaces to throttle
  Manager* manager_;
  // For I/O handling with the spawned process
  IOHandlerFactory* io_handler_factory_;
  // For spawning 'tc'
  ProcessManager* process_manager_;

  base::WeakPtrFactory<Throttler> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_THROTTLER_H_
