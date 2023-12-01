// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ICMP_SESSION_H_
#define SHILL_ICMP_SESSION_H_

#include <netinet/ip_icmp.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/time/default_tick_clock.h>
#include <base/time/tick_clock.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/icmp.h"
#include "shill/net/io_handler.h"

namespace shill {

class EventDispatcher;
class IOHandlerFactory;
class IPAddress;

// The IcmpSession class encapsulates the task of performing a stateful exchange
// of echo requests and echo replies between this host and another (i.e. ping).
// The Icmp class is used to perform the sending of echo requests. Each
// IcmpSession object only allows one ICMP session to be running at one time.
// Multiple ICMP sessions can be run concurrently by creating multiple
// IcmpSession objects.
class IcmpSession {
 public:
  // The result of an ICMP session is a vector of time deltas representing how
  // long it took to receive a echo reply for each sent echo request. The vector
  // is sorted in the order that the echo requests were sent. Zero time deltas
  // represent echo requests that we did not receive a corresponding reply for.
  using IcmpSessionResult = std::vector<base::TimeDelta>;
  using IcmpSessionResultCallback =
      base::OnceCallback<void(const IcmpSessionResult&)>;

  explicit IcmpSession(EventDispatcher* dispatcher);
  IcmpSession(const IcmpSession&) = delete;
  IcmpSession& operator=(const IcmpSession&) = delete;

  // We always call IcmpSession::Stop in the destructor to clean up, in case an
  // ICMP session is still in progress.
  virtual ~IcmpSession();

  // Starts an ICMP session, sending |kNumEchoRequestsToSend| echo requests to
  // |destination|, |kEchoRequestInterval| apart. |result_callback| will
  // be called a) after all echo requests are sent and all echo replies are
  // received, or b) after |kTimeout| have passed. |result_callback| will
  // only be invoked once on the first occurrence of either of these events.
  // |interface_index| is the IPv6 scope ID, which can be 0 for a global
  // |destination| but must be a positive integer if |destination| is a
  // link-local address. It is unused on IPv4.
  virtual bool Start(const IPAddress& destination,
                     int interface_index,
                     IcmpSessionResultCallback result_callback);

  // Stops the current ICMP session by closing the ICMP socket and resetting
  // callbacks. Does nothing if a ICMP session is not started.
  virtual void Stop();

  // Returns true if this ICMP session has started, or false otherwise.
  bool IsStarted() const;

  // Utility function that returns false iff |result| indicates that no echo
  // replies were received to any ICMP echo request that was sent during the
  // ICMP session that generated |result|.
  static bool AnyRepliesReceived(const IcmpSessionResult& result);

  // Utility function that returns the packet loss rate for the ICMP session
  // that generated |result| is greater than |percentage_threshold| percent.
  // The percentage packet loss determined by this function will be rounded
  // down to the closest integer percentage value. |percentage_threshold| is
  // expected to be a non-negative integer value.
  static bool IsPacketLossPercentageGreaterThan(const IcmpSessionResult& result,
                                                int percentage_threshold);

 private:
  using SentRecvTimePair = std::pair<base::TimeTicks, base::TimeTicks>;

  friend class IcmpSessionTest;

  FRIEND_TEST(IcmpSessionTest, Constructor);  // for |echo_id_|

  static uint16_t kNextUniqueEchoId;  // unique across IcmpSession objects
  static constexpr int kTotalNumEchoRequests = 3;
  // default for ping
  static constexpr base::TimeDelta kEchoRequestInterval = base::Seconds(1);
  // We should not need more than 1 second after the last request is sent to
  // receive the final reply.
  static constexpr base::TimeDelta kTimeout =
      kEchoRequestInterval * kTotalNumEchoRequests + base::Seconds(1);

  // Sends a single echo request to the destination. This function will call
  // itself repeatedly via the event loop every |kEchoRequestInterval|
  // until |kNumEchoRequestToSend| echo requests are sent or the timeout is
  // reached.
  void TransmitEchoRequestTask();

  // Called when an ICMP packet is received.
  void OnEchoReplyReceived(InputData* data);

  // IPv4 and IPv6 packet parsers.
  int OnV4EchoReplyReceived(InputData* data);
  int OnV6EchoReplyReceived(InputData* data);

  // Helper function that generates the result of the current ICMP session.
  IcmpSessionResult GenerateIcmpResult();

  // Called when the input handler |echo_reply_handler_| encounters an error.
  void OnEchoReplyError(const std::string& error_msg);

  // Calls |result_callback_| with the results collected so far, then stops the
  // IcmpSession. This function is called when the ICMP session successfully
  // completes, or when it times out. Does nothing if an ICMP session is not
  // started.
  void ReportResultAndStopSession();

  base::WeakPtrFactory<IcmpSession> weak_ptr_factory_;
  EventDispatcher* dispatcher_;
  IOHandlerFactory* io_handler_factory_;
  std::unique_ptr<Icmp> icmp_;
  const uint16_t echo_id_;  // unique ID for this object's echo request/replies
  uint16_t current_sequence_number_;
  std::map<uint16_t, SentRecvTimePair> seq_num_to_sent_recv_time_;
  std::set<uint16_t> received_echo_reply_seq_numbers_;
  // Allow for an injectable tick clock for testing.
  base::TickClock* tick_clock_;
  base::DefaultTickClock default_tick_clock_;
  base::CancelableOnceClosure timeout_callback_;
  IcmpSessionResultCallback result_callback_;
  std::unique_ptr<IOHandler> echo_reply_handler_;
};

}  // namespace shill

#endif  // SHILL_ICMP_SESSION_H_
