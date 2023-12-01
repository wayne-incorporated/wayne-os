// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_RTNL_LINK_STATS_H_
#define SHILL_NET_RTNL_LINK_STATS_H_

#include <stdint.h>

// Pre-v4.6 layout for rtnl_link_stats64. Linux commit 6e7333d315a7 ("net: add
// rx_nohandler stat counter") added an additional field, and for pre-v4.6
// compatibility, we just ignore it.
// TODO(briannorris): drop this when older kernels are phased out.
struct old_rtnl_link_stats64 {
  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t rx_bytes;
  uint64_t tx_bytes;
  uint64_t rx_errors;
  uint64_t tx_errors;
  uint64_t rx_dropped;
  uint64_t tx_dropped;
  uint64_t multicast;
  uint64_t collisions;

  // detailed rx_errors
  uint64_t rx_length_errors;
  uint64_t rx_over_errors;
  uint64_t rx_crc_errors;
  uint64_t rx_frame_errors;
  uint64_t rx_fifo_errors;
  uint64_t rx_missed_errors;

  // detailed tx_errors
  uint64_t tx_aborted_errors;
  uint64_t tx_carrier_errors;
  uint64_t tx_fifo_errors;
  uint64_t tx_heartbeat_errors;
  uint64_t tx_window_errors;

  // for cslip etc
  uint64_t rx_compressed;
  uint64_t tx_compressed;
};

#endif  // SHILL_NET_RTNL_LINK_STATS_H_
