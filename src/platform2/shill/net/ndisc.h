// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_NDISC_H_
#define SHILL_NET_NDISC_H_

// Neighbor discovery related definitions. This is needed because kernel
// currently does not export these definitions to the user space.

// Netlink multicast group for neighbor discovery user option message.
#define RTMGRP_ND_USEROPT 0x80000

// Neighbor Discovery user option header definition.
struct NDUserOptionHeader {
  NDUserOptionHeader() { memset(this, 0, sizeof(*this)); }
  uint8_t type;
  uint8_t length;
  uint16_t reserved;
  uint32_t lifetime;
} __attribute__((__packed__));

// Neighbor Discovery user option type definition.
#define ND_OPT_RDNSS 25 /* RFC 5006 */
#define ND_OPT_DNSSL 31 /* RFC 6106 */

// Infinity lifetime.
#define ND_OPT_LIFETIME_INFINITY 0xFFFFFFFF

#endif  // SHILL_NET_NDISC_H_
