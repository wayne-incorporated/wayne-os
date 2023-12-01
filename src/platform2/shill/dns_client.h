// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DNS_CLIENT_H_
#define SHILL_DNS_CLIENT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/net/ip_address.h"
#include "shill/refptr_types.h"

struct hostent;

namespace shill {

class Ares;
class IOHandlerFactory;
class Time;
struct DnsClientState;

// Implements a DNS resolution client that can run asynchronously.
class DnsClient {
 public:
  using ClientCallback =
      base::RepeatingCallback<void(const Error&, const IPAddress&)>;

  static const char kErrorNoData[];
  static const char kErrorFormErr[];
  static const char kErrorServerFail[];
  static const char kErrorNotFound[];
  static const char kErrorNotImp[];
  static const char kErrorRefused[];
  static const char kErrorBadQuery[];
  static const char kErrorNetRefused[];
  static const char kErrorTimedOut[];
  static const char kErrorUnknown[];

  static const int kDnsTimeoutMilliseconds = 8000;

  DnsClient(IPAddress::Family family,
            const std::string& interface_name,
            int timeout_ms,
            EventDispatcher* dispatcher,
            const ClientCallback& callback);
  DnsClient(const DnsClient&) = delete;
  DnsClient& operator=(const DnsClient&) = delete;

  virtual ~DnsClient();

  // Returns true if the DNS client started successfully, false otherwise.
  // If successful, the callback will be called with the result of the
  // request.  If Start() fails and returns false, the callback will not
  // be called, but the error that caused the failure will be returned in
  // |error|.
  virtual bool Start(const std::vector<std::string>& dns_list,
                     const std::string& hostname,
                     Error* error);

  // Aborts any running DNS client transaction.  This will cancel any callback
  // invocation.
  virtual void Stop();

  virtual bool IsActive() const;

  std::string interface_name() const { return interface_name_; }

 private:
  friend class DnsClientTest;

  void HandleCompletion();
  void HandleDnsRead(int fd);
  void HandleDnsWrite(int fd);
  void HandleTimeout();
  void ProcessFd(int read_fd, int write_fd);
  void ReceiveDnsReply(int status, struct hostent* hostent);
  static void ReceiveDnsReplyCB(void* arg,
                                int status,
                                int timeouts,
                                struct hostent* hostent);
  bool RefreshHandles();
  void StopReadHandlers();
  void StopWriteHandlers();

  Error error_;
  IPAddress address_;
  std::string interface_name_;
  EventDispatcher* dispatcher_;
  IOHandlerFactory* io_handler_factory_;
  ClientCallback callback_;
  int timeout_ms_;
  bool running_;
  std::unique_ptr<DnsClientState> resolver_state_;
  base::CancelableOnceClosure timeout_closure_;
  base::WeakPtrFactory<DnsClient> weak_ptr_factory_;
  Ares* ares_;
  Time* time_;
};

}  // namespace shill

#endif  // SHILL_DNS_CLIENT_H_
