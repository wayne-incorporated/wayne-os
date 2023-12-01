// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wake_on_wifi.h"

#include <linux/nl80211.h>

#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/stringprintf.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/logging.h"
#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_log.h"
#include "shill/mock_metrics.h"
#include "shill/net/byte_string.h"
#include "shill/net/ip_address.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/net/mock_time.h"
#include "shill/net/netlink_message_matchers.h"
#include "shill/net/netlink_packet.h"
#include "shill/net/nl80211_message.h"
#include "shill/net/shill_time.h"
#include "shill/test_event_dispatcher.h"
#include "shill/testing.h"

using testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::HasSubstr;
using ::testing::Mock;
using ::testing::Return;

namespace shill {

namespace {

const uint16_t kNl80211FamilyId = 0x13;

const uint8_t kSSIDBytes1[] = {0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
                               0x47, 0x75, 0x65, 0x73, 0x74};
// Bytes representing a NL80211_CMD_SET_WOWLAN reporting that the system woke
// up because of an SSID match. The net detect results report a single SSID
// match represented by kSSIDBytes1, occurring in the frequencies in
// kSSID1FreqMatches.
const uint8_t kWakeReasonSSIDNlMsg[] = {
    0x90, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x99, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x60, 0x00, 0x75, 0x00, 0x5c, 0x00, 0x13, 0x00, 0x58, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x34, 0x00, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x47, 0x75,
    0x65, 0x73, 0x74, 0x00, 0x44, 0x00, 0x2c, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x6c, 0x09, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x85, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x9e, 0x09, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
    0x3c, 0x14, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x78, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x05, 0x00, 0x71, 0x16, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xad, 0x16, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0xc1, 0x16, 0x00, 0x00};
constexpr base::TimeDelta kTimeToNextLeaseRenewalShort = base::Seconds(1);
constexpr base::TimeDelta kTimeToNextLeaseRenewalLong = base::Seconds(1000);
const uint32_t kNetDetectScanIntervalSeconds = 120;
// These blobs represent NL80211 messages from the kernel reporting the NIC's
// wake on WiFi settings, sent in response to NL80211_CMD_GET_WOWLAN requests.
const uint8_t kResponseNoWake[] = {0x14, 0x00, 0x00, 0x00, 0x13, 0x00, 0x01,
                                   0x00, 0x01, 0x00, 0x00, 0x00, 0x57, 0x40,
                                   0x00, 0x00, 0x49, 0x01, 0x00, 0x00};
// This blob represents an NL80211 messages that the NIC is programmed to wake
// on disconnect.
const uint8_t kResponseWakeOnDisconnect[] = {
    0x1c, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x57, 0x40, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00,
    0x08, 0x00, 0x75, 0x00, 0x04, 0x00, 0x02, 0x00};
// This blob represents an NL80211 messages from the kernel reporting that the
// NIC is programmed to wake on the SSIDs represented by kSSIDBytes1 and
// kSSIDBytes2, and scans for these SSIDs at interval
// kNetDetectScanIntervalSeconds.
const uint8_t kResponseWakeOnSSID[] = {
    0x60, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x9a, 0x01, 0x00, 0x00,
    0xfa, 0x02, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00, 0x4c, 0x01, 0x75, 0x00,
    0x48, 0x01, 0x12, 0x00, 0x08, 0x00, 0x77, 0x00, 0xc0, 0xd4, 0x01, 0x00,
    0x0c, 0x01, 0x2c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x6c, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x71, 0x09, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
    0x76, 0x09, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x7b, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x80, 0x09, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00,
    0x85, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x8a, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x07, 0x00, 0x8f, 0x09, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
    0x94, 0x09, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0x99, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x0a, 0x00, 0x9e, 0x09, 0x00, 0x00, 0x08, 0x00, 0x0b, 0x00,
    0x3c, 0x14, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x50, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x0d, 0x00, 0x64, 0x14, 0x00, 0x00, 0x08, 0x00, 0x0e, 0x00,
    0x78, 0x14, 0x00, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x8c, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x10, 0x00, 0xa0, 0x14, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00,
    0xb4, 0x14, 0x00, 0x00, 0x08, 0x00, 0x12, 0x00, 0xc8, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x13, 0x00, 0x7c, 0x15, 0x00, 0x00, 0x08, 0x00, 0x14, 0x00,
    0x90, 0x15, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00, 0xa4, 0x15, 0x00, 0x00,
    0x08, 0x00, 0x16, 0x00, 0xb8, 0x15, 0x00, 0x00, 0x08, 0x00, 0x17, 0x00,
    0xcc, 0x15, 0x00, 0x00, 0x08, 0x00, 0x18, 0x00, 0x1c, 0x16, 0x00, 0x00,
    0x08, 0x00, 0x19, 0x00, 0x30, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1a, 0x00,
    0x44, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1b, 0x00, 0x58, 0x16, 0x00, 0x00,
    0x08, 0x00, 0x1c, 0x00, 0x71, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1d, 0x00,
    0x85, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1e, 0x00, 0x99, 0x16, 0x00, 0x00,
    0x08, 0x00, 0x1f, 0x00, 0xad, 0x16, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00,
    0xc1, 0x16, 0x00, 0x00, 0x30, 0x00, 0x84, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x0f, 0x00, 0x01, 0x00, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x47, 0x75,
    0x65, 0x73, 0x74, 0x00, 0x18, 0x00, 0x01, 0x00, 0x12, 0x00, 0x01, 0x00,
    0x54, 0x50, 0x2d, 0x4c, 0x49, 0x4e, 0x4b, 0x5f, 0x38, 0x37, 0x36, 0x44,
    0x33, 0x35, 0x00, 0x00};
const uint8_t kSSIDBytes2[] = {0x54, 0x50, 0x2d, 0x4c, 0x49, 0x4e, 0x4b,
                               0x5f, 0x38, 0x37, 0x36, 0x44, 0x33, 0x35};

// Bytes representing a NL80211_CMD_NEW_WIPHY message reporting the WiFi
// capabilities of a NIC.
// This message reports that the NIC supports:
// - wake on pattern (on up to 20 registered patterns)
// - wake on SSID (on up to |kNewWiphyNlMsg_MaxSSIDs| SSIDs)
// - wake on disconnect
const uint8_t kNewWiphyNlMsg[] = {
    0xb8, 0x0d, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0xd9, 0x53, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x70, 0x68, 0x79, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x3d, 0x00, 0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x3e, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3f, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x08, 0x00, 0x40, 0x00, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00, 0x59, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2b, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x7b, 0x00, 0x14, 0x00, 0x00, 0x00, 0x06, 0x00, 0x38, 0x00,
    0xa9, 0x01, 0x00, 0x00, 0x06, 0x00, 0x7c, 0x00, 0xe6, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x85, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x04, 0x00, 0x68, 0x00,
    0x04, 0x00, 0x82, 0x00, 0x1c, 0x00, 0x39, 0x00, 0x04, 0xac, 0x0f, 0x00,
    0x02, 0xac, 0x0f, 0x00, 0x01, 0xac, 0x0f, 0x00, 0x05, 0xac, 0x0f, 0x00,
    0x06, 0xac, 0x0f, 0x00, 0x01, 0x72, 0x14, 0x00, 0x05, 0x00, 0x56, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x66, 0x00, 0x08, 0x00, 0x71, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x24, 0x00, 0x20, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x06, 0x00,
    0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00, 0x04, 0x00, 0x0a, 0x00,
    0x94, 0x05, 0x16, 0x00, 0xe8, 0x01, 0x00, 0x00, 0x14, 0x00, 0x03, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0xe2, 0x11, 0x00, 0x00,
    0x05, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x18, 0x01, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x6c, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x71, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x14, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x76, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x7b, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x80, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x14, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x85, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x8a, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x8f, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x00, 0x94, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x09, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x99, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x14, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x9e, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x1c, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x01, 0x00, 0xa3, 0x09, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xa8, 0x09, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0xa0, 0x00, 0x02, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x02, 0x00, 0x10, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x37, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x10, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x6e, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x0c, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x5a, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x78, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x09, 0x00, 0x08, 0x00, 0x01, 0x00, 0x68, 0x01, 0x00, 0x00,
    0x0c, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00,
    0x0c, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x01, 0x00, 0x1c, 0x02, 0x00, 0x00,
    0xa8, 0x03, 0x01, 0x00, 0x14, 0x00, 0x03, 0x00, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x01, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x04, 0x00, 0xe2, 0x11, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x07, 0x00, 0xfa, 0xff, 0x00, 0x00, 0xfa, 0xff, 0x00, 0x00,
    0x08, 0x00, 0x08, 0x00, 0xa0, 0x71, 0x80, 0x03, 0x00, 0x03, 0x01, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x3c, 0x14, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x50, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x64, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x1c, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x78, 0x14, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x8c, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x20, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0xa0, 0x14, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xb4, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xc8, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x20, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x00, 0x7c, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x09, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x90, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xa4, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x20, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x01, 0x00, 0xb8, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x0c, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xcc, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xe0, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x20, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x01, 0x00, 0xf4, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x0f, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x08, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x10, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x1c, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x20, 0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x00, 0x30, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x12, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x44, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x20, 0x00, 0x13, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x58, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x1c, 0x00, 0x14, 0x00, 0x08, 0x00, 0x01, 0x00, 0x71, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x15, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x85, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x16, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x99, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00,
    0x1c, 0x00, 0x17, 0x00, 0x08, 0x00, 0x01, 0x00, 0xad, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x98, 0x08, 0x00, 0x00, 0x1c, 0x00, 0x18, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xc1, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x98, 0x08, 0x00, 0x00, 0x64, 0x00, 0x02, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x5a, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x78, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0x68, 0x01, 0x00, 0x00,
    0x0c, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00,
    0x0c, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x1c, 0x02, 0x00, 0x00,
    0xdc, 0x00, 0x32, 0x00, 0x08, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x05, 0x00, 0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x19, 0x00, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00, 0x25, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x08, 0x00, 0x26, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00,
    0x27, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00, 0x28, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x0b, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00,
    0x37, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00, 0x39, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x0e, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0f, 0x00,
    0x43, 0x00, 0x00, 0x00, 0x08, 0x00, 0x10, 0x00, 0x31, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x11, 0x00, 0x41, 0x00, 0x00, 0x00, 0x08, 0x00, 0x12, 0x00,
    0x42, 0x00, 0x00, 0x00, 0x08, 0x00, 0x13, 0x00, 0x4b, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x14, 0x00, 0x54, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00,
    0x57, 0x00, 0x00, 0x00, 0x08, 0x00, 0x16, 0x00, 0x55, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x17, 0x00, 0x59, 0x00, 0x00, 0x00, 0x08, 0x00, 0x18, 0x00,
    0x5c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x19, 0x00, 0x2d, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x1a, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1b, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x08, 0x00, 0x6f, 0x00, 0x10, 0x27, 0x00, 0x00,
    0x04, 0x00, 0x6c, 0x00, 0x30, 0x04, 0x63, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x01, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xe0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x02, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xe0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x03, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xe0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x84, 0x00, 0x04, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xe0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x06, 0x00, 0x84, 0x00, 0x07, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x84, 0x00, 0x08, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x84, 0x00, 0x09, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x84, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x30, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x70, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x90, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xe0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x40, 0x01, 0x64, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x03, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x04, 0x00, 0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x06, 0x00, 0x1c, 0x00, 0x07, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xc0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x08, 0x00, 0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x09, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xb0, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00, 0xc0, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x0a, 0x00,
    0x06, 0x00, 0x65, 0x00, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x65, 0x00,
    0xd0, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x76, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x06, 0x00,
    0x04, 0x00, 0x07, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00,
    0x14, 0x00, 0x04, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x12, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x79, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x06, 0x00, 0x60, 0x00, 0x78, 0x00, 0x5c, 0x00, 0x01, 0x00,
    0x48, 0x00, 0x01, 0x00, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x1c, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x02, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x08, 0x00,
    0x04, 0x00, 0x09, 0x00, 0x14, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x04, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x8f, 0x00, 0xe3, 0x1a, 0x00, 0x07,
    0x1e, 0x00, 0x94, 0x00, 0x63, 0x48, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0xa9, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x0c, 0x00, 0xaa, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40};

const uint32_t kNewWiphyNlMsg_MaxSSIDs = 11;
const int kNewWiphyNlMsg_WowlanTrigNetDetectAttributeOffset = 3316;
const int kNewWiphyNlMsg_WowlanTrigDisconnectAttributeOffset = 3268;

const uint32_t kSSID1FreqMatches[] = {2412, 2437, 2462, 5180,
                                      5240, 5745, 5805, 5825};

const uint32_t kWakeReasonNlMsg_WiphyIndex = 0;
// NL80211_CMD_GET_WOWLAN message with nlmsg_type 0x16, which is different from
// kNl80211FamilyId (0x13).
const uint8_t kWrongMessageTypeNlMsg[] = {
    0x14, 0x00, 0x00, 0x00, 0x16, 0x00, 0x01, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x57, 0x40, 0x00, 0x00, 0x49, 0x01, 0x00, 0x00};
// Bytes representing a NL80211_CMD_SET_WOWLAN reporting that the system woke
// up because of a reason other than wake on WiFi.
const uint8_t kWakeReasonUnsupportedNlMsg[] = {
    0x30, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x99, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00};
// Bytes representing a NL80211_CMD_SET_WOWLAN reporting that the system woke
// up because of a disconnect.
const uint8_t kWakeReasonDisconnectNlMsg[] = {
    0x38, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x4a, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x99, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x75, 0x00, 0x04, 0x00, 0x02, 0x00};
}  // namespace

class WakeOnWiFiTest : public ::testing::Test {
 public:
  WakeOnWiFiTest() = default;
  ~WakeOnWiFiTest() override = default;

  void SetUp() override {
    Error unused_error;

    Nl80211Message::SetMessageType(kNl80211FamilyId);
    // Try to set the feature allowed by default in tests.
    wake_on_wifi_->SetWakeOnWiFiAllowed(true, &unused_error);
    // Assume our NIC has reported its wiphy index, and that it supports wake
    // all wake triggers.
    wake_on_wifi_->wiphy_index_received_ = true;
    wake_on_wifi_->wake_on_wifi_triggers_supported_.insert(
        WakeOnWiFi::kWakeTriggerDisconnect);
    wake_on_wifi_->wake_on_wifi_triggers_supported_.insert(
        WakeOnWiFi::kWakeTriggerSSID);
    // By default our tests assume that the NIC supports more SSIDs than
    // allowed SSIDs.
    wake_on_wifi_->wake_on_wifi_max_ssids_ = 999;
    wake_on_wifi_->dark_resume_history_.time_ = &time_;

    // Change timer for testing.
    wake_on_wifi_->wake_to_scan_timer_ =
        brillo::timers::SimpleAlarmTimer::CreateForTesting();
    wake_on_wifi_->dhcp_lease_renewal_timer_ =
        brillo::timers::SimpleAlarmTimer::CreateForTesting();

    ON_CALL(netlink_manager_, SendNl80211Message(_, _, _, _))
        .WillByDefault(Return(true));
  }

  void SetWakeOnWiFiMaxSSIDs(uint32_t max_ssids) {
    wake_on_wifi_->wake_on_wifi_max_ssids_ = max_ssids;
  }

  void EnableWakeOnWiFiFeaturesDarkConnect() {
    wake_on_wifi_->wake_on_wifi_features_enabled_ =
        kWakeOnWiFiFeaturesEnabledDarkConnect;
  }

  void DisableWakeOnWiFiFeatures() {
    wake_on_wifi_->wake_on_wifi_features_enabled_ =
        kWakeOnWiFiFeaturesEnabledNone;
  }

  bool ConfigureWiphyIndex(Nl80211Message* msg, int32_t index) {
    return WakeOnWiFi::ConfigureWiphyIndex(msg, index);
  }

  bool ConfigureDisableWakeOnWiFiMessage(SetWakeOnWiFiMessage* msg,
                                         uint32_t wiphy_index,
                                         Error* error) {
    return WakeOnWiFi::ConfigureDisableWakeOnWiFiMessage(msg, wiphy_index,
                                                         error);
  }

  bool WakeOnWiFiSettingsMatch(
      const Nl80211Message& msg,
      const std::set<WakeOnWiFi::WakeOnWiFiTrigger>& trigs,
      uint32_t net_detect_scan_period_seconds,
      const std::vector<ByteString>& allowed_ssids) {
    return WakeOnWiFi::WakeOnWiFiSettingsMatch(
        msg, trigs, net_detect_scan_period_seconds, allowed_ssids);
  }

  bool ConfigureSetWakeOnWiFiSettingsMessage(
      SetWakeOnWiFiMessage* msg,
      const std::set<WakeOnWiFi::WakeOnWiFiTrigger>& trigs,
      uint32_t wiphy_index,
      uint32_t net_detect_scan_period_seconds,
      const std::vector<ByteString>& allowed_ssids,
      Error* error) {
    return WakeOnWiFi::ConfigureSetWakeOnWiFiSettingsMessage(
        msg, trigs, wiphy_index, net_detect_scan_period_seconds, allowed_ssids,
        error);
  }

  void RequestWakeOnWiFiSettings() {
    wake_on_wifi_->RequestWakeOnWiFiSettings();
  }

  void VerifyWakeOnWiFiSettings(const Nl80211Message& nl80211_message) {
    wake_on_wifi_->VerifyWakeOnWiFiSettings(nl80211_message);
  }

  uint32_t GetWakeOnWiFiMaxSSIDs() {
    return wake_on_wifi_->wake_on_wifi_max_ssids_;
  }

  void ApplyWakeOnWiFiSettings() { wake_on_wifi_->ApplyWakeOnWiFiSettings(); }

  void DisableWakeOnWiFi() { wake_on_wifi_->DisableWakeOnWiFi(); }

  std::set<WakeOnWiFi::WakeOnWiFiTrigger>* GetWakeOnWiFiTriggers() {
    return &wake_on_wifi_->wake_on_wifi_triggers_;
  }

  std::set<WakeOnWiFi::WakeOnWiFiTrigger>* GetWakeOnWiFiTriggersSupported() {
    return &wake_on_wifi_->wake_on_wifi_triggers_supported_;
  }

  void ClearWakeOnWiFiTriggersSupported() {
    wake_on_wifi_->wake_on_wifi_triggers_supported_.clear();
  }

  void RetrySetWakeOnWiFiConnections() {
    wake_on_wifi_->RetrySetWakeOnWiFiConnections();
  }

  void SetSuspendActionsDoneCallback() {
    wake_on_wifi_->suspend_actions_done_callback_ =
        base::BindOnce(&WakeOnWiFiTest::DoneCallback, base::Unretained(this));
  }

  void ResetSuspendActionsDoneCallback() {
    wake_on_wifi_->suspend_actions_done_callback_.Reset();
  }

  bool SuspendActionsCallbackIsNull() {
    return wake_on_wifi_->suspend_actions_done_callback_.is_null();
  }

  void RunSuspendActionsCallback(const Error& error) {
    std::move(wake_on_wifi_->suspend_actions_done_callback_).Run(error);
  }

  int GetNumSetWakeOnWiFiRetries() {
    return wake_on_wifi_->num_set_wake_on_wifi_retries_;
  }

  void SetConnectedBeforeSuspend(bool was_connected) {
    wake_on_wifi_->connected_before_suspend_ = was_connected;
  }

  void SetNumSetWakeOnWiFiRetries(int retries) {
    wake_on_wifi_->num_set_wake_on_wifi_retries_ = retries;
  }

  void OnBeforeSuspend(
      bool is_connected,
      const std::vector<ByteString>& allowed_ssids,
      std::optional<base::TimeDelta> time_to_next_lease_renewal) {
    ResultCallback done_callback(
        base::BindOnce(&WakeOnWiFiTest::DoneCallback, base::Unretained(this)));
    base::OnceClosure renew_dhcp_lease_callback(base::BindOnce(
        &WakeOnWiFiTest::RenewDHCPLeaseCallback, base::Unretained(this)));
    base::OnceClosure remove_supplicant_networks_callback(
        base::BindOnce(&WakeOnWiFiTest::RemoveSupplicantNetworksCallback,
                       base::Unretained(this)));
    wake_on_wifi_->OnBeforeSuspend(
        is_connected, allowed_ssids, std::move(done_callback),
        std::move(renew_dhcp_lease_callback),
        std::move(remove_supplicant_networks_callback),
        time_to_next_lease_renewal);
  }

  void OnDarkResume(bool is_connected,
                    const std::vector<ByteString>& allowed_ssids) {
    ResultCallback done_callback(
        base::BindOnce(&WakeOnWiFiTest::DoneCallback, base::Unretained(this)));
    base::OnceClosure renew_dhcp_lease_callback(base::BindOnce(
        &WakeOnWiFiTest::RenewDHCPLeaseCallback, base::Unretained(this)));
    WakeOnWiFi::InitiateScanCallback initiate_scan_callback(base::BindOnce(
        &WakeOnWiFiTest::InitiateScanCallback, base::Unretained(this)));
    base::RepeatingClosure remove_supplicant_networks_callback(
        base::BindRepeating(&WakeOnWiFiTest::RemoveSupplicantNetworksCallback,
                            base::Unretained(this)));
    wake_on_wifi_->OnDarkResume(
        is_connected, allowed_ssids, std::move(done_callback),
        std::move(renew_dhcp_lease_callback), std::move(initiate_scan_callback),
        remove_supplicant_networks_callback);
  }

  void OnAfterResume() { wake_on_wifi_->OnAfterResume(); }

  void BeforeSuspendActions(
      bool is_connected,
      std::optional<base::TimeDelta> time_to_next_lease_renewal) {
    SetDarkResumeActionsTimeOutCallback();
    EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());
    base::OnceClosure remove_supplicant_networks_callback(
        base::BindOnce(&WakeOnWiFiTest::RemoveSupplicantNetworksCallback,
                       base::Unretained(this)));
    wake_on_wifi_->BeforeSuspendActions(
        is_connected, time_to_next_lease_renewal,
        std::move(remove_supplicant_networks_callback));
    EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  }

  void OnConnectedAndReachable(
      std::optional<base::TimeDelta> time_to_next_lease_renewal) {
    wake_on_wifi_->OnConnectedAndReachable(time_to_next_lease_renewal);
  }

  void SetInDarkResume(bool val) { wake_on_wifi_->in_dark_resume_ = val; }

  bool GetInDarkResume() { return wake_on_wifi_->in_dark_resume_; }

  void SetWiphyIndexReceivedToFalse() {
    wake_on_wifi_->wiphy_index_received_ = false;
  }

  void SetWiphyIndex(uint32_t wiphy_index) {
    wake_on_wifi_->wiphy_index_ = wiphy_index;
  }

  void ParseWakeOnWiFiCapabilities(const Nl80211Message& nl80211_message) {
    wake_on_wifi_->ParseWakeOnWiFiCapabilities(nl80211_message);
  }

  bool SetWakeOnWiFiAllowed(bool allowed, Error* error) {
    return wake_on_wifi_->SetWakeOnWiFiAllowed(allowed, error);
  }

  bool SetWakeOnWiFiFeaturesEnabled(const std::string& enabled, Error* error) {
    return wake_on_wifi_->SetWakeOnWiFiFeaturesEnabled(enabled, error);
  }

  bool GetWakeOnWiFiAllowed() {
    Error error;
    bool allowed = wake_on_wifi_->GetWakeOnWiFiAllowed(&error);
    EXPECT_TRUE(error.IsSuccess());
    return allowed;
  }

  const std::string& GetWakeOnWiFiFeaturesEnabled() {
    return wake_on_wifi_->wake_on_wifi_features_enabled_;
  }

  void SetDarkResumeActionsTimeOutCallback() {
    wake_on_wifi_->dark_resume_actions_timeout_callback_.Reset(
        base::BindOnce(&WakeOnWiFiTest::DarkResumeActionsTimeoutCallback,
                       base::Unretained(this)));
  }

  bool DarkResumeActionsTimeOutCallbackIsCancelled() {
    return wake_on_wifi_->dark_resume_actions_timeout_callback_.IsCancelled();
  }

  void StartDHCPLeaseRenewalTimer() {
    wake_on_wifi_->dhcp_lease_renewal_timer_->Start(
        FROM_HERE, kTimeToNextLeaseRenewalLong, base::DoNothing());
  }

  void StartWakeToScanTimer() {
    wake_on_wifi_->wake_to_scan_timer_->Start(
        FROM_HERE, kTimeToNextLeaseRenewalLong, base::DoNothing());
  }

  void StopDHCPLeaseRenewalTimer() {
    wake_on_wifi_->dhcp_lease_renewal_timer_->Stop();
  }

  void StopWakeToScanTimer() { wake_on_wifi_->wake_to_scan_timer_->Stop(); }

  bool DHCPLeaseRenewalTimerIsRunning() {
    return wake_on_wifi_->dhcp_lease_renewal_timer_->IsRunning();
  }

  bool WakeToScanTimerIsRunning() {
    return wake_on_wifi_->wake_to_scan_timer_->IsRunning();
  }

  void SetDarkResumeActionsTimeout(base::TimeDelta timeout) {
    wake_on_wifi_->DarkResumeActionsTimeout = timeout;
  }

  void InitStateForDarkResume() {
    SetInDarkResume(true);
    EnableWakeOnWiFiFeaturesDarkConnect();
    SetDarkResumeActionsTimeout(base::TimeDelta());
  }

  void SetExpectationsDisconnectedBeforeSuspend() {
    EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
    EXPECT_CALL(*this, DoneCallback(_)).Times(0);
    EXPECT_CALL(*this, RemoveSupplicantNetworksCallback()).Times(1);
    EXPECT_CALL(
        netlink_manager_,
        SendNl80211Message(
            IsNl80211Command(kNl80211FamilyId, SetWakeOnWiFiMessage::kCommand),
            _, _, _));
  }

  void SetExpectationsConnectedBeforeSuspend() {
    EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
    EXPECT_CALL(*this, DoneCallback(_)).Times(0);
    EXPECT_CALL(
        netlink_manager_,
        SendNl80211Message(
            IsNl80211Command(kNl80211FamilyId, SetWakeOnWiFiMessage::kCommand),
            _, _, _));
  }

  void VerifyStateConnectedBeforeSuspend() {
    EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
    EXPECT_FALSE(GetInDarkResume());
    EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
    EXPECT_TRUE(
        GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerDisconnect) !=
        GetWakeOnWiFiTriggers()->end());
  }

  void VerifyStateDisconnectedBeforeSuspend() {
    EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
    EXPECT_FALSE(GetInDarkResume());
    EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
    EXPECT_TRUE(GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerSSID) !=
                GetWakeOnWiFiTriggers()->end());
  }

  void OnNoAutoConnectableServicesAfterScan(
      const std::vector<ByteString>& allowed_ssids) {
    base::OnceClosure remove_supplicant_networks_callback(
        base::BindOnce(&WakeOnWiFiTest::RemoveSupplicantNetworksCallback,
                       base::Unretained(this)));
    WakeOnWiFi::InitiateScanCallback initiate_scan_callback(base::BindOnce(
        &WakeOnWiFiTest::InitiateScanCallback, base::Unretained(this)));
    wake_on_wifi_->OnNoAutoConnectableServicesAfterScan(
        allowed_ssids, std::move(remove_supplicant_networks_callback),
        std::move(initiate_scan_callback));
  }

  EventHistory* GetDarkResumeHistory() {
    return &wake_on_wifi_->dark_resume_history_;
  }

  void SetNetDetectScanPeriodSeconds(uint32_t period) {
    wake_on_wifi_->net_detect_scan_period_seconds_ = period;
  }

  void AllowSSID(const uint8_t* ssid,
                 int num_bytes,
                 std::vector<ByteString>* allowed) {
    std::vector<uint8_t> ssid_vector(ssid, ssid + num_bytes);
    allowed->push_back(ByteString(ssid_vector));
  }

  std::vector<ByteString>* GetWakeOnAllowedSSIDs() {
    return &wake_on_wifi_->wake_on_allowed_ssids_;
  }

  void OnWakeupReasonReceived(const NetlinkMessage& netlink_message) {
    wake_on_wifi_->OnWakeupReasonReceived(netlink_message);
  }

  WiFi::FreqSet ParseWakeOnSSIDResults(AttributeListConstRefPtr results_list) {
    return wake_on_wifi_->ParseWakeOnSSIDResults(results_list);
  }

  NetlinkMessage::MessageContext GetWakeupReportMsgContext() {
    NetlinkMessage::MessageContext context;
    context.nl80211_cmd = NL80211_CMD_SET_WOWLAN;
    context.is_broadcast = true;
    return context;
  }

  void SetLastWakeReason(WakeOnWiFi::WakeOnWiFiTrigger reason) {
    wake_on_wifi_->last_wake_reason_ = reason;
  }

  WakeOnWiFi::WakeOnWiFiTrigger GetLastWakeReason() {
    return wake_on_wifi_->last_wake_reason_;
  }

  void OnScanStarted(bool is_active_scan) {
    wake_on_wifi_->OnScanStarted(is_active_scan);
  }

  const WiFi::FreqSet& GetLastSSIDMatchFreqs() {
    return wake_on_wifi_->last_ssid_match_freqs_;
  }

  void AddResultToLastSSIDResults() {
    wake_on_wifi_->last_ssid_match_freqs_.insert(1);
  }

  void InitiateScanInDarkResume(const WiFi::FreqSet& freqs) {
    wake_on_wifi_->InitiateScanInDarkResume(
        base::BindOnce(&WakeOnWiFiTest::InitiateScanCallback,
                       base::Unretained(this)),
        freqs);
  }

  int GetDarkResumeScanRetriesLeft() {
    return wake_on_wifi_->dark_resume_scan_retries_left_;
  }

  void SetDarkResumeScanRetriesLeft(int retries) {
    wake_on_wifi_->dark_resume_scan_retries_left_ = retries;
  }

  Timestamp GetTimestampBootTime(int boottime_seconds) {
    struct timeval monotonic = {.tv_sec = 0, .tv_usec = 0};
    struct timeval boottime = {.tv_sec = boottime_seconds, .tv_usec = 0};
    return Timestamp(monotonic, boottime, "");
  }

  MOCK_METHOD(void, DoneCallback, (const Error&));
  MOCK_METHOD(void, RenewDHCPLeaseCallback, ());
  MOCK_METHOD(void, InitiateScanCallback, (const WiFi::FreqSet&));
  MOCK_METHOD(void, RemoveSupplicantNetworksCallback, ());
  MOCK_METHOD(void, DarkResumeActionsTimeoutCallback, ());
  MOCK_METHOD(void, RecordDarkResumeWakeReasonCallback, (const std::string&));

 protected:
  MockControl control_interface_;
  MockMetrics metrics_;
  MockNetlinkManager netlink_manager_;
  MockTime time_;
  std::unique_ptr<WakeOnWiFi> wake_on_wifi_;
};

class WakeOnWiFiTestWithDispatcher : public WakeOnWiFiTest {
 public:
  WakeOnWiFiTestWithDispatcher() : WakeOnWiFiTest() {
    wake_on_wifi_.reset(new WakeOnWiFi(
        &netlink_manager_, &dispatcher_, &metrics_,
        base::BindRepeating(&WakeOnWiFiTest::RecordDarkResumeWakeReasonCallback,
                            base::Unretained(this))));
  }
  virtual ~WakeOnWiFiTestWithDispatcher() = default;

 protected:
  EventDispatcherForTest dispatcher_;
};

class WakeOnWiFiTestWithMockDispatcher : public WakeOnWiFiTest {
 public:
  WakeOnWiFiTestWithMockDispatcher() : WakeOnWiFiTest() {
    wake_on_wifi_.reset(new WakeOnWiFi(
        &netlink_manager_, &mock_dispatcher_, &metrics_,
        base::BindRepeating(&WakeOnWiFiTest::RecordDarkResumeWakeReasonCallback,
                            base::Unretained(this))));
  }
  virtual ~WakeOnWiFiTestWithMockDispatcher() = default;

 protected:
  // TODO(zqiu): TaskRunner is needed by AlarmTimer, temporarily provide with
  // TaskEnvironment, Should restructure the code so that it can be mocked out.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::MainThreadType::IO};
  MockEventDispatcher mock_dispatcher_;
};

TEST_F(WakeOnWiFiTestWithMockDispatcher, ConfigureWiphyIndex) {
  SetWakeOnWiFiMessage msg;
  uint32_t value;
  EXPECT_FALSE(
      msg.attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY, &value));

  ConfigureWiphyIndex(&msg, 137);
  EXPECT_TRUE(
      msg.attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY, &value));
  EXPECT_EQ(value, 137);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, ConfigureDisableWakeOnWiFiMessage) {
  SetWakeOnWiFiMessage msg;
  Error e;
  uint32_t value;
  EXPECT_FALSE(
      msg.attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY, &value));

  ConfigureDisableWakeOnWiFiMessage(&msg, 57, &e);
  EXPECT_EQ(e.type(), Error::Type::kSuccess);
  EXPECT_TRUE(
      msg.attributes()->GetU32AttributeValue(NL80211_ATTR_WIPHY, &value));
  EXPECT_EQ(value, 57);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, WakeOnWiFiSettingsMatch_Disconnect) {
  std::set<WakeOnWiFi::WakeOnWiFiTrigger> trigs;
  std::vector<ByteString> allowed;
  const uint32_t interval = kNetDetectScanIntervalSeconds;

  // Initialize test messages.
  GetWakeOnWiFiMessage msgNoWake;
  NetlinkPacket packetNoWake(kResponseNoWake, sizeof(kResponseNoWake));
  msgNoWake.InitFromPacket(&packetNoWake, NetlinkMessage::MessageContext());

  GetWakeOnWiFiMessage msgWakeOnDisconnect;
  NetlinkPacket packetWakeOnDisconnect(kResponseWakeOnDisconnect,
                                       sizeof(kResponseWakeOnDisconnect));
  msgWakeOnDisconnect.InitFromPacket(&packetWakeOnDisconnect,
                                     NetlinkMessage::MessageContext());

  GetWakeOnWiFiMessage msgWakeOnSSID;
  NetlinkPacket packetWakeOnSSID(kResponseWakeOnSSID,
                                 sizeof(kResponseWakeOnSSID));
  msgWakeOnSSID.InitFromPacket(&packetWakeOnSSID,
                               NetlinkMessage::MessageContext());

  // No trigger.
  EXPECT_TRUE(WakeOnWiFiSettingsMatch(msgNoWake, trigs, interval, allowed));
  EXPECT_FALSE(
      WakeOnWiFiSettingsMatch(msgWakeOnDisconnect, trigs, interval, allowed));
  EXPECT_FALSE(
      WakeOnWiFiSettingsMatch(msgWakeOnSSID, trigs, interval, allowed));

  // Wake on disconnect.
  trigs.insert(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_TRUE(
      WakeOnWiFiSettingsMatch(msgWakeOnDisconnect, trigs, interval, allowed));
  EXPECT_FALSE(WakeOnWiFiSettingsMatch(msgNoWake, trigs, interval, allowed));
  EXPECT_FALSE(
      WakeOnWiFiSettingsMatch(msgWakeOnSSID, trigs, interval, allowed));

  // Wake on SSID.
  trigs.clear();
  trigs.insert(WakeOnWiFi::kWakeTriggerSSID);
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  AllowSSID(kSSIDBytes2, sizeof(kSSIDBytes2), &allowed);
  EXPECT_TRUE(WakeOnWiFiSettingsMatch(msgWakeOnSSID, trigs, interval, allowed));
  EXPECT_FALSE(WakeOnWiFiSettingsMatch(msgNoWake, trigs, interval, allowed));
  EXPECT_FALSE(
      WakeOnWiFiSettingsMatch(msgWakeOnDisconnect, trigs, interval, allowed));
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ConfigureSetWakeOnWiFiSettingsMessage) {
  std::set<WakeOnWiFi::WakeOnWiFiTrigger> trigs;
  const int index = 1;  // wiphy device number
  std::vector<ByteString> allowed;
  const uint32_t interval = kNetDetectScanIntervalSeconds;
  Error e;

  SetWakeOnWiFiMessage msgWakeOnDisconnect;
  trigs.insert(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_TRUE(ConfigureSetWakeOnWiFiSettingsMessage(
      &msgWakeOnDisconnect, trigs, index, interval, allowed, &e));
  EXPECT_TRUE(
      WakeOnWiFiSettingsMatch(msgWakeOnDisconnect, trigs, interval, allowed));

  SetWakeOnWiFiMessage msgWakeOnSSID;
  trigs.clear();
  trigs.insert(WakeOnWiFi::kWakeTriggerSSID);
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  AllowSSID(kSSIDBytes2, sizeof(kSSIDBytes2), &allowed);
  EXPECT_TRUE(ConfigureSetWakeOnWiFiSettingsMessage(
      &msgWakeOnSSID, trigs, index, interval, allowed, &e));
  EXPECT_TRUE(WakeOnWiFiSettingsMatch(msgWakeOnSSID, trigs, interval, allowed));
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, RequestWakeOnWiFiSettings) {
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, GetWakeOnWiFiMessage::kCommand), _,
          _, _))
      .Times(1);
  RequestWakeOnWiFiSettings();
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       VerifyWakeOnWiFiSettings_WakeOnDisconnectRules) {
  ScopedMockLog log;
  // Create a non-trivial Nl80211 response to a NL80211_CMD_GET_WOWLAN request
  // indicating that the NIC wakes on disconnects.
  GetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kResponseWakeOnDisconnect,
                       sizeof(kResponseWakeOnDisconnect));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  // Successful verification and consequent invocation of callback.
  SetSuspendActionsDoneCallback();
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(2);
  EXPECT_CALL(*this, DoneCallback(ErrorTypeIs(Error::kSuccess))).Times(1);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log, Log(_, _, HasSubstr("Wake on WiFi settings successfully verified")));
  VerifyWakeOnWiFiSettings(msg);
  // Suspend action callback cleared after being invoked.
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);

  // Unsuccessful verification if locally stored settings do not match.
  GetWakeOnWiFiTriggers()->erase(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log,
      Log(logging::LOGGING_ERROR, _,
          HasSubstr(" failed: discrepancy between wake-on-packet settings on "
                    "NIC and those in local data structure detected")));
  VerifyWakeOnWiFiSettings(msg);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       VerifyWakeOnWiFiSettings_WakeOnSSIDRules) {
  ScopedMockLog log;
  // Create a non-trivial Nl80211 response to a NL80211_CMD_GET_WOWLAN request
  // indicating that that the NIC wakes on two SSIDs represented by kSSIDBytes1
  // and kSSIDBytes2 and scans for them at interval
  // kNetDetectScanIntervalSeconds.
  GetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kResponseWakeOnSSID, sizeof(kResponseWakeOnSSID));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  // Successful verification and consequent invocation of callback.
  SetSuspendActionsDoneCallback();
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerSSID);
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), GetWakeOnAllowedSSIDs());
  AllowSSID(kSSIDBytes2, sizeof(kSSIDBytes2), GetWakeOnAllowedSSIDs());
  SetNetDetectScanPeriodSeconds(kNetDetectScanIntervalSeconds);
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(2);
  EXPECT_CALL(*this, DoneCallback(ErrorTypeIs(Error::kSuccess))).Times(1);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log, Log(_, _, HasSubstr("Wake on WiFi settings successfully verified")));
  VerifyWakeOnWiFiSettings(msg);
  // Suspend action callback cleared after being invoked.
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       VerifyWakeOnWiFiSettingsSuccess_NoDoneCallback) {
  ScopedMockLog log;
  // Create an Nl80211 response to a NL80211_CMD_GET_WOWLAN request
  // indicating that there are no wake-on-WiFi rules programmed into the NIC.
  GetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kResponseNoWake, sizeof(kResponseNoWake));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  // Successful verification, but since there is no suspend action callback
  // set, no callback is invoked.
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(2);
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log, Log(_, _, HasSubstr("Wake on WiFi settings successfully verified")));
  VerifyWakeOnWiFiSettings(msg);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       RetrySetWakeOnWiFiConnections_LessThanMaxRetries) {
  ScopedMockLog log;
  // Max retries not reached yet, so send Nl80211 message to program NIC again.
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  SetNumSetWakeOnWiFiRetries(WakeOnWiFi::kMaxSetWakeOnWiFiRetries - 1);
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, SetWakeOnWiFiMessage::kCommand), _,
          _, _))
      .Times(1);
  RetrySetWakeOnWiFiConnections();
  EXPECT_EQ(GetNumSetWakeOnWiFiRetries(), WakeOnWiFi::kMaxSetWakeOnWiFiRetries);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       RetrySetWakeOnWiFiConnections_MaxAttemptsWithCallbackSet) {
  ScopedMockLog log;
  // Max retry attempts reached. Suspend actions done callback is set, so it
  // is invoked.
  SetNumSetWakeOnWiFiRetries(WakeOnWiFi::kMaxSetWakeOnWiFiRetries);
  SetSuspendActionsDoneCallback();
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
  EXPECT_CALL(*this, DoneCallback(ErrorTypeIs(Error::kOperationFailed)))
      .Times(1);
  EXPECT_CALL(netlink_manager_, SendNl80211Message(_, _, _, _)).Times(0);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(_, _, HasSubstr("max retry attempts reached")));
  RetrySetWakeOnWiFiConnections();
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  EXPECT_EQ(GetNumSetWakeOnWiFiRetries(), 0);
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       RetrySetWakeOnWiFiConnections_MaxAttemptsCallbackUnset) {
  ScopedMockLog log;
  // If there is no suspend action callback set, no suspend callback should be
  // invoked.
  SetNumSetWakeOnWiFiRetries(WakeOnWiFi::kMaxSetWakeOnWiFiRetries);
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(_, _, HasSubstr("max retry attempts reached")));
  RetrySetWakeOnWiFiConnections();
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ParseWakeOnWiFiCapabilities_DisconnectSSIDSupported) {
  ClearWakeOnWiFiTriggersSupported();
  NewWiphyMessage msg;
  NetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  ParseWakeOnWiFiCapabilities(msg);
  EXPECT_TRUE(GetWakeOnWiFiTriggersSupported()->find(
                  WakeOnWiFi::kWakeTriggerDisconnect) !=
              GetWakeOnWiFiTriggersSupported()->end());
  EXPECT_TRUE(
      GetWakeOnWiFiTriggersSupported()->find(WakeOnWiFi::kWakeTriggerSSID) !=
      GetWakeOnWiFiTriggersSupported()->end());
  EXPECT_EQ(GetWakeOnWiFiMaxSSIDs(), kNewWiphyNlMsg_MaxSSIDs);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ParseWakeOnWiFiCapabilities_DisconnectNotSupported) {
  ClearWakeOnWiFiTriggersSupported();
  NewWiphyMessage msg;
  // Change the NL80211_WOWLAN_TRIG_DISCONNECT flag attribute into the
  // NL80211_WOWLAN_TRIG_MAGIC_PKT flag attribute, so that this message
  // no longer reports wake on disconnect as a supported capability.
  MutableNetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  struct nlattr* wowlan_trig_disconnect_attr = reinterpret_cast<struct nlattr*>(
      &packet.GetMutablePayload()
           ->GetData()[kNewWiphyNlMsg_WowlanTrigDisconnectAttributeOffset]);
  wowlan_trig_disconnect_attr->nla_type = NL80211_WOWLAN_TRIG_MAGIC_PKT;
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  ParseWakeOnWiFiCapabilities(msg);
  EXPECT_TRUE(
      GetWakeOnWiFiTriggersSupported()->find(WakeOnWiFi::kWakeTriggerSSID) !=
      GetWakeOnWiFiTriggersSupported()->end());
  // Ensure that ParseWakeOnWiFiCapabilities realizes that wake on disconnect
  // is not supported.
  EXPECT_FALSE(GetWakeOnWiFiTriggersSupported()->find(
                   WakeOnWiFi::kWakeTriggerDisconnect) !=
               GetWakeOnWiFiTriggersSupported()->end());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ParseWakeOnWiFiCapabilities_SSIDNotSupported) {
  ClearWakeOnWiFiTriggersSupported();
  NewWiphyMessage msg;
  // Change the NL80211_WOWLAN_TRIG_NET_DETECT flag attribute type to an invalid
  // attribute type (0), so that this message no longer reports wake on SSID
  // as a supported capability.
  MutableNetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  struct nlattr* wowlan_trig_net_detect_attr = reinterpret_cast<struct nlattr*>(
      &packet.GetMutablePayload()
           ->GetData()[kNewWiphyNlMsg_WowlanTrigNetDetectAttributeOffset]);
  wowlan_trig_net_detect_attr->nla_type = 0;
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  ParseWakeOnWiFiCapabilities(msg);
  EXPECT_TRUE(GetWakeOnWiFiTriggersSupported()->find(
                  WakeOnWiFi::kWakeTriggerDisconnect) !=
              GetWakeOnWiFiTriggersSupported()->end());
  // Ensure that ParseWakeOnWiFiCapabilities realizes that wake on SSID is not
  // supported.
  EXPECT_FALSE(
      GetWakeOnWiFiTriggersSupported()->find(WakeOnWiFi::kWakeTriggerSSID) !=
      GetWakeOnWiFiTriggersSupported()->end());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ApplyWakeOnWiFiSettings_WiphyIndexNotReceived) {
  ScopedMockLog log;
  // ApplyWakeOnWiFiSettings should return immediately if the wifi interface
  // index has not been received when the function is called.
  SetWiphyIndexReceivedToFalse();
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(0);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(logging::LOGGING_ERROR, _,
                       HasSubstr("Interface index not yet received")));
  ApplyWakeOnWiFiSettings();
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       ApplyWakeOnWiFiSettings_WiphyIndexReceived) {
  // Disable wake on WiFi if there are no wake on WiFi triggers registered.
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, SetWakeOnWiFiMessage::kCommand), _,
          _, _))
      .Times(0);
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(1);
  ApplyWakeOnWiFiSettings();

  // Otherwise, program the NIC.
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, SetWakeOnWiFiMessage::kCommand), _,
          _, _))
      .Times(1);
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(0);
  ApplyWakeOnWiFiSettings();
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       BeforeSuspendActions_ReportDoneImmediately) {
  ScopedMockLog log;
  const bool is_connected = true;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), GetWakeOnAllowedSSIDs());
  // If no triggers are supported, no triggers will be programmed into the NIC.
  ClearWakeOnWiFiTriggersSupported();
  SetSuspendActionsDoneCallback();
  SetInDarkResume(true);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  // Do not report done immediately in dark resume, since we need to program it
  // to disable wake on WiFi.
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());

  SetInDarkResume(false);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  // Report done immediately on normal suspend, since wake on WiFi should
  // already have been disabled on the NIC on a previous resume.
  EXPECT_CALL(*this, DoneCallback(_)).Times(1);
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(1);
  EXPECT_CALL(
      log,
      Log(_, _,
          HasSubstr(
              "No need to disable wake on WiFi on NIC in regular suspend")));
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       BeforeSuspendActions_FeaturesDisabledOrTriggersUnsupported) {
  const bool is_connected = true;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), GetWakeOnAllowedSSIDs());
  SetInDarkResume(false);
  SetSuspendActionsDoneCallback();
  // No features enabled, so no triggers programmed.
  DisableWakeOnWiFiFeatures();
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  EXPECT_CALL(*this, DoneCallback(_));
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());

  // No triggers supported, so no triggers programmed.
  SetSuspendActionsDoneCallback();
  EnableWakeOnWiFiFeaturesDarkConnect();
  GetWakeOnWiFiTriggersSupported()->clear();
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  EXPECT_CALL(*this, DoneCallback(_));
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());

  // Only wake on disconnect and wake on SSID supported.
  EnableWakeOnWiFiFeaturesDarkConnect();
  GetWakeOnWiFiTriggersSupported()->clear();
  GetWakeOnWiFiTriggersSupported()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  GetWakeOnWiFiTriggersSupported()->insert(WakeOnWiFi::kWakeTriggerSSID);
  GetWakeOnWiFiTriggers()->clear();
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(
      GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerDisconnect) !=
      GetWakeOnWiFiTriggers()->end());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       BeforeSuspendActions_ConnectedBeforeSuspend) {
  const bool is_connected = true;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), GetWakeOnAllowedSSIDs());
  SetSuspendActionsDoneCallback();
  EnableWakeOnWiFiFeaturesDarkConnect();

  SetInDarkResume(true);
  GetWakeOnWiFiTriggers()->clear();
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  StartWakeToScanTimer();
  StopDHCPLeaseRenewalTimer();
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_TRUE(WakeToScanTimerIsRunning());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(
      GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerDisconnect) !=
      GetWakeOnWiFiTriggers()->end());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       BeforeSuspendActions_DisconnectedBeforeSuspend) {
  const bool is_connected = false;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), GetWakeOnAllowedSSIDs());
  AllowSSID(kSSIDBytes2, sizeof(kSSIDBytes2), GetWakeOnAllowedSSIDs());
  SetSuspendActionsDoneCallback();
  EnableWakeOnWiFiFeaturesDarkConnect();

  // Do not start wake to scan timer if there are less alloweded SSIDs (2)
  // than net detect SSIDs we support (10).
  SetInDarkResume(true);
  GetWakeOnWiFiTriggers()->clear();
  StopWakeToScanTimer();
  StartDHCPLeaseRenewalTimer();
  SetWakeOnWiFiMaxSSIDs(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_EQ(2, GetWakeOnAllowedSSIDs()->size());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_EQ(2, GetWakeOnAllowedSSIDs()->size());
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerSSID) !=
              GetWakeOnWiFiTriggers()->end());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());

  // Start wake to scan timer if there are more alloweded SSIDs (2) than
  // net detect SSIDs we support (1). Also, truncate the wake on SSID list
  // so that it only contains as many SSIDs as we support (1).
  SetInDarkResume(true);
  GetWakeOnWiFiTriggers()->clear();
  StopWakeToScanTimer();
  StartDHCPLeaseRenewalTimer();
  SetWakeOnWiFiMaxSSIDs(1);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_EQ(2, GetWakeOnAllowedSSIDs()->size());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_EQ(1, GetWakeOnAllowedSSIDs()->size());
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerSSID) !=
              GetWakeOnWiFiTriggers()->end());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_TRUE(WakeToScanTimerIsRunning());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());

  // Neither add the wake on SSID trigger nor start the wake to scan timer if
  // there are no alloweded SSIDs.
  SetInDarkResume(true);
  GetWakeOnAllowedSSIDs()->clear();
  StopWakeToScanTimer();
  StartDHCPLeaseRenewalTimer();
  SetWakeOnWiFiMaxSSIDs(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  AddResultToLastSSIDResults();
  EXPECT_TRUE(GetWakeOnAllowedSSIDs()->empty());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_CALL(*this, DoneCallback(_)).Times(0);
  BeforeSuspendActions(is_connected,
                       std::make_optional(kTimeToNextLeaseRenewalLong));
  EXPECT_TRUE(GetWakeOnAllowedSSIDs()->empty());
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, DisableWakeOnWiFi_ClearsTriggers) {
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_FALSE(GetWakeOnWiFiTriggers()->empty());
  DisableWakeOnWiFi();
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->empty());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, ParseWakeOnSSIDResults) {
  SetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kWakeReasonSSIDNlMsg, sizeof(kWakeReasonSSIDNlMsg));
  msg.InitFromPacket(&packet, GetWakeupReportMsgContext());
  AttributeListConstRefPtr triggers;
  ASSERT_TRUE(msg.const_attributes()->ConstGetNestedAttributeList(
      NL80211_ATTR_WOWLAN_TRIGGERS, &triggers));
  AttributeListConstRefPtr results_list;
  ASSERT_TRUE(triggers->ConstGetNestedAttributeList(
      NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS, &results_list));
  WiFi::FreqSet freqs = ParseWakeOnSSIDResults(results_list);
  EXPECT_EQ(std::size(kSSID1FreqMatches), freqs.size());
  for (uint32_t freq : kSSID1FreqMatches) {
    EXPECT_TRUE(freqs.find(freq) != freqs.end());
  }
}

TEST_F(WakeOnWiFiTestWithDispatcher, InitiateScanInDarkResume) {
  WiFi::FreqSet freqs;

  // If we are not scanning on specific frequencies, do not enable the retry
  // mechanism.
  EXPECT_EQ(0, GetDarkResumeScanRetriesLeft());
  EXPECT_CALL(*this, InitiateScanCallback(freqs));
  InitiateScanInDarkResume(freqs);
  EXPECT_EQ(0, GetDarkResumeScanRetriesLeft());

  // Otherwise, start channel specific passive scan with retries.
  freqs.insert(1);
  EXPECT_LE(freqs.size(), WakeOnWiFi::kMaxFreqsForDarkResumeScanRetries);
  EXPECT_EQ(0, GetDarkResumeScanRetriesLeft());
  EXPECT_CALL(*this, InitiateScanCallback(freqs));
  InitiateScanInDarkResume(freqs);
  EXPECT_EQ(WakeOnWiFi::kMaxDarkResumeScanRetries,
            GetDarkResumeScanRetriesLeft());
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnBeforeSuspend_SetsWakeOnAllowedSSIDs) {
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_TRUE(GetWakeOnAllowedSSIDs()->empty());
  OnBeforeSuspend(true, allowed, std::make_optional(base::TimeDelta()));
  EXPECT_FALSE(GetWakeOnAllowedSSIDs()->empty());
  EXPECT_EQ(1, GetWakeOnAllowedSSIDs()->size());
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnBeforeSuspend_SetsDoneCallback) {
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  OnBeforeSuspend(true, allowed, std::make_optional(base::TimeDelta()));
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnBeforeSuspend_DHCPLeaseRenewal) {
  bool is_connected;
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  // Disable all features.
  DisableWakeOnWiFiFeatures();

  // When no feature enabled, we'll not renew DHCP.
  is_connected = true;
  EXPECT_CALL(*this, RenewDHCPLeaseCallback()).Times(0);
  OnBeforeSuspend(is_connected, allowed,
                  std::make_optional(kTimeToNextLeaseRenewalShort));
  Mock::VerifyAndClearExpectations(this);

  // Enable a feature for the following tests.
  EnableWakeOnWiFiFeaturesDarkConnect();

  // If we are connected the time to next lease renewal is short enough, we will
  // initiate DHCP lease renewal immediately.
  is_connected = true;
  EXPECT_CALL(*this, RenewDHCPLeaseCallback()).Times(1);
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(1);
  OnBeforeSuspend(is_connected, allowed,
                  std::make_optional(kTimeToNextLeaseRenewalShort));

  // No immediate DHCP lease renewal because we are not connected.
  is_connected = false;
  EXPECT_CALL(*this, RenewDHCPLeaseCallback()).Times(0);
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(1);
  OnBeforeSuspend(is_connected, allowed,
                  std::make_optional(kTimeToNextLeaseRenewalShort));

  // No immediate DHCP lease renewal because the time to the next lease renewal
  // is longer than the threshold.
  is_connected = true;
  EXPECT_CALL(*this, RenewDHCPLeaseCallback()).Times(0);
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(1);
  OnBeforeSuspend(is_connected, allowed,
                  std::make_optional(kTimeToNextLeaseRenewalLong));

  // No immediate DHCP lease renewal because we do not have a DHCP lease that
  // needs to be renewed.
  is_connected = true;
  EXPECT_CALL(*this, RenewDHCPLeaseCallback()).Times(0);
  EXPECT_CALL(mock_dispatcher_, PostDelayedTask(_, _, base::TimeDelta()))
      .Times(1);
  OnBeforeSuspend(is_connected, allowed, std::nullopt);
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnDarkResume_ResetsDarkResumeScanRetries) {
  const bool is_connected = true;
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();
  SetDarkResumeScanRetriesLeft(3);
  EXPECT_EQ(3, GetDarkResumeScanRetriesLeft());
  OnDarkResume(is_connected, allowed);
  EXPECT_EQ(0, GetDarkResumeScanRetriesLeft());
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnDarkResume_SetsWakeOnAllowedSSIDs) {
  const bool is_connected = true;
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_TRUE(GetWakeOnAllowedSSIDs()->empty());
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(GetWakeOnAllowedSSIDs()->empty());
  EXPECT_EQ(1, GetWakeOnAllowedSSIDs()->size());
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonUnsupported_Connected_Timeout) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while connected, then timeout on suspend actions
  // before suspending again.
  const bool is_connected = true;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Renew DHCP lease if we are connected in dark resume.
  EXPECT_CALL(*this, RenewDHCPLeaseCallback());
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Trigger timeout callback.
  // Since we timeout, we are disconnected before suspend.
  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  dispatcher_.DispatchPendingEvents();
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonUnsupported_Connected_NoAutoconnectableServices) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while connected, then go back to suspend because
  // we could not find any services available for autoconnect.
  const bool is_connected = true;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Renew DHCP lease if we are connected in dark resume.
  EXPECT_CALL(*this, RenewDHCPLeaseCallback());
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonUnsupported_Connected_LeaseObtained) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while connected, then connect and obtain a DHCP
  // lease before suspending again.
  const bool is_connected = true;
  constexpr base::TimeDelta time_to_next_lease_renewal = base::Seconds(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Renew DHCP lease if we are connected in dark resume.
  EXPECT_CALL(*this, RenewDHCPLeaseCallback());
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Lease obtained.
  // Since a lease is obtained, we are connected before suspend.
  StopDHCPLeaseRenewalTimer();
  StartWakeToScanTimer();
  SetExpectationsConnectedBeforeSuspend();
  OnConnectedAndReachable(std::make_optional(time_to_next_lease_renewal));
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  VerifyStateConnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonUnsupported_NotConnected_Timeout) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while not connected, then timeout on suspend
  // actions before suspending again.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Initiate scan if we are not connected in dark resume.
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Trigger timeout callback.
  // Since we timeout, we are disconnected before suspend.
  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  dispatcher_.DispatchPendingEvents();
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(
    WakeOnWiFiTestWithDispatcher,
    OnDarkResume_WakeReasonUnsupported_NotConnected_NoAutoconnectableServices) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while not connected, then go back to suspend
  // because we could not find any services available for autoconnect.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Initiate scan if we are not connected in dark resume.
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonUnsupported_NotConnected_LeaseObtained) {
  // Test that correct actions are taken if we enter OnDarkResume on an
  // unsupported wake trigger while connected, then connect and obtain a DHCP
  // lease before suspending again.
  const bool is_connected = false;
  constexpr base::TimeDelta time_to_next_lease_renewal = base::Seconds(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerUnsupported);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Initiate scan if we are not connected in dark resume.
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());
  // Lease obtained.
  // Since a lease is obtained, we are connected before suspend.
  StopDHCPLeaseRenewalTimer();
  StartWakeToScanTimer();
  SetExpectationsConnectedBeforeSuspend();
  OnConnectedAndReachable(std::make_optional(time_to_next_lease_renewal));
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  VerifyStateConnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonDisconnect_NoAutoconnectableServices) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on a disconnect, and go back to suspend because we could not
  // find any networks available for autoconnect.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonDisconnect_Timeout) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on a disconnect, then timeout on suspend actions before
  // suspending again.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonDisconnect_LeaseObtained) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on a disconnect, then connect and obtain a DHCP lease before
  // suspending again.
  const bool is_connected = false;
  constexpr base::TimeDelta time_to_next_lease_renewal = base::Seconds(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerDisconnect);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StopDHCPLeaseRenewalTimer();
  StartWakeToScanTimer();
  SetExpectationsConnectedBeforeSuspend();
  OnConnectedAndReachable(std::make_optional(time_to_next_lease_renewal));
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  VerifyStateConnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonSSID_NoAutoconnectableServices) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on SSID, and go back to suspend because we could not find any
  // networks available for autoconnect.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerSSID);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(_));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnDarkResume_WakeReasonSSID_Timeout) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on SSID, then timeout on suspend actions before suspending
  // again.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerSSID);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(GetLastSSIDMatchFreqs()));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StartDHCPLeaseRenewalTimer();
  SetExpectationsDisconnectedBeforeSuspend();
  dispatcher_.DispatchPendingEvents();
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  VerifyStateDisconnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_WakeReasonSSID_LeaseObtained) {
  // Test that correct actions are taken if we enter dark resume because the
  // system woke on SSID, then connect and obtain a DHCP lease before suspending
  // again.
  const bool is_connected = false;
  constexpr base::TimeDelta time_to_next_lease_renewal = base::Seconds(10);
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerSSID);
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);

  InitStateForDarkResume();
  EXPECT_TRUE(DarkResumeActionsTimeOutCallbackIsCancelled());
  EXPECT_CALL(*this, RemoveSupplicantNetworksCallback());
  EXPECT_CALL(*this, InitiateScanCallback(GetLastSSIDMatchFreqs()));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(DarkResumeActionsTimeOutCallbackIsCancelled());

  StopDHCPLeaseRenewalTimer();
  StartWakeToScanTimer();
  SetExpectationsConnectedBeforeSuspend();
  OnConnectedAndReachable(std::make_optional(time_to_next_lease_renewal));
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  VerifyStateConnectedBeforeSuspend();
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnDarkResume_Connected_DoNotRecordEvent) {
  const bool is_connected = true;
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());
  OnDarkResume(is_connected, allowed);
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());
}

TEST_F(WakeOnWiFiTestWithDispatcher, OnDarkResume_NotConnected_RecordEvent) {
  const bool is_connected = false;
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());
  OnDarkResume(is_connected, allowed);
  EXPECT_EQ(1, GetDarkResumeHistory()->Size());
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_NotConnected_MaxDarkResumes_ShortPeriod) {
  // These 3 dark resume timings are within a 1 minute interval, so as to
  // trigger the short throttling threshold (3 in 1 minute).
  const int kTimeSeconds[] = {10, 20, 30};
  CHECK_EQ(static_cast<const unsigned int>(
               WakeOnWiFi::kMaxDarkResumesPerPeriodShort),
           std::size(kTimeSeconds));
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();

  // This test assumes that throttling takes place when 3 dark resumes have
  // been triggered in the last 1 minute.
  EXPECT_EQ(3, WakeOnWiFi::kMaxDarkResumesPerPeriodShort);
  EXPECT_EQ(1, WakeOnWiFi::kDarkResumeFrequencySamplingPeriodShort.InMinutes());

  // Wake on SSID dark resumes should be recorded in the dark resume history.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerSSID);
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());

  // First two dark resumes take place at 10 and 20 seconds respectively. This
  // is still within the throttling threshold.
  for (int i = 0; i < WakeOnWiFi::kMaxDarkResumesPerPeriodShort - 1; ++i) {
    EXPECT_CALL(time_, GetNow())
        .WillRepeatedly(Return(GetTimestampBootTime(kTimeSeconds[i])));
    OnDarkResume(is_connected, allowed);
  }
  SetInDarkResume(false);  // this happens after BeforeSuspendActions
  EXPECT_EQ(WakeOnWiFi::kMaxDarkResumesPerPeriodShort - 1,
            GetDarkResumeHistory()->Size());

  // The 3rd dark resume takes place at 30 seconds, which makes 3 dark resumes
  // in the past minute. Disable wake on WiFi and start wake to scan timer.
  ResetSuspendActionsDoneCallback();
  StartDHCPLeaseRenewalTimer();
  StopWakeToScanTimer();
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_FALSE(GetDarkResumeHistory()->Empty());
  EXPECT_CALL(time_, GetNow())
      .WillRepeatedly(Return(GetTimestampBootTime(
          kTimeSeconds[WakeOnWiFi::kMaxDarkResumesPerPeriodShort - 1])));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_TRUE(WakeToScanTimerIsRunning());
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());
  EXPECT_FALSE(GetInDarkResume());
}

TEST_F(WakeOnWiFiTestWithDispatcher,
       OnDarkResume_NotConnected_MaxDarkResumes_LongPeriod) {
  // These 10 dark resume timings are spaced 1 minute apart so as to trigger the
  // long throttling threshold (10 in 10 minute) without triggering the short
  // throttling threshold (3 in 1 minute).
  const int kTimeSeconds[] = {10, 70, 130, 190, 250, 310, 370, 430, 490, 550};
  CHECK_EQ(
      static_cast<const unsigned int>(WakeOnWiFi::kMaxDarkResumesPerPeriodLong),
      std::size(kTimeSeconds));
  std::vector<ByteString> allowed;
  EnableWakeOnWiFiFeaturesDarkConnect();

  // This test assumes that throttling takes place when 3 dark resumes have been
  // triggered in the last 1 minute, or when 10 dark resumes have been triggered
  // in the last 10 minutes.
  EXPECT_EQ(3, WakeOnWiFi::kMaxDarkResumesPerPeriodShort);
  EXPECT_EQ(1, WakeOnWiFi::kDarkResumeFrequencySamplingPeriodShort.InMinutes());
  EXPECT_EQ(10, WakeOnWiFi::kMaxDarkResumesPerPeriodLong);
  EXPECT_EQ(10, WakeOnWiFi::kDarkResumeFrequencySamplingPeriodLong.InMinutes());

  // Wake on SSID dark resumes should be recorded in the dark resume history.
  const bool is_connected = false;
  SetLastWakeReason(WakeOnWiFi::kWakeTriggerSSID);
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());

  // The first 9 dark resumes happen once per minute. This is still within the
  // throttling threshold.
  for (int i = 0; i < WakeOnWiFi::kMaxDarkResumesPerPeriodLong - 1; ++i) {
    EXPECT_CALL(time_, GetNow())
        .WillRepeatedly(Return(GetTimestampBootTime(kTimeSeconds[i])));
    OnDarkResume(is_connected, allowed);
  }
  SetInDarkResume(false);  // this happens after BeforeSuspendActions
  EXPECT_EQ(WakeOnWiFi::kMaxDarkResumesPerPeriodLong - 1,
            GetDarkResumeHistory()->Size());

  // The occurrence of the 10th dark resume makes 10 dark resumes in the past 10
  // minutes. Disable wake on WiFi and start wake to scan timer.
  ResetSuspendActionsDoneCallback();
  StartDHCPLeaseRenewalTimer();
  StopWakeToScanTimer();
  EXPECT_TRUE(SuspendActionsCallbackIsNull());
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_FALSE(GetDarkResumeHistory()->Empty());
  EXPECT_CALL(time_, GetNow())
      .WillRepeatedly(Return(GetTimestampBootTime(
          kTimeSeconds[WakeOnWiFi::kMaxDarkResumesPerPeriodLong - 1])));
  OnDarkResume(is_connected, allowed);
  EXPECT_FALSE(SuspendActionsCallbackIsNull());
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_TRUE(WakeToScanTimerIsRunning());
  EXPECT_TRUE(GetDarkResumeHistory()->Empty());
  EXPECT_FALSE(GetInDarkResume());
  EXPECT_TRUE(GetLastSSIDMatchFreqs().empty());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnConnectedAndReachable) {
  ScopedMockLog log;

  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EnableWakeOnWiFiFeaturesDarkConnect();
  SetInDarkResume(true);
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  EXPECT_CALL(log, Log(_, _, HasSubstr("BeforeSuspendActions")))
      .Times(AtLeast(1));
  OnConnectedAndReachable(std::make_optional(kTimeToNextLeaseRenewalLong));

  SetInDarkResume(false);
  EXPECT_CALL(log, Log(_, _, HasSubstr("Not in dark resume")));
  OnConnectedAndReachable(std::make_optional(kTimeToNextLeaseRenewalLong));
  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, WakeOnWiFiDisabledAfterResume) {
  // At least one wake on WiFi trigger supported and Wake on WiFi features
  // are enabled, so disable Wake on WiFi on resume.]
  EnableWakeOnWiFiFeaturesDarkConnect();
  GetWakeOnWiFiTriggers()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(1);
  OnAfterResume();

  // No wake no WiFi triggers supported, so do nothing.
  ClearWakeOnWiFiTriggersSupported();
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(0);
  OnAfterResume();

  // Wake on WiFi features disabled, so do nothing.
  GetWakeOnWiFiTriggersSupported()->insert(WakeOnWiFi::kWakeTriggerDisconnect);
  DisableWakeOnWiFiFeatures();
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(0);
  OnAfterResume();

  // Both WakeOnWiFi triggers are empty and Wake on WiFi features are disabled,
  // so do nothing.
  ClearWakeOnWiFiTriggersSupported();
  DisableWakeOnWiFiFeatures();
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(IsDisableWakeOnWiFiMsg(), _, _, _))
      .Times(0);
  OnAfterResume();
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, SetWakeOnWiFiAllowed) {
  Error e;
  DisableWakeOnWiFiFeatures();

  // Turn off allowed property.
  EXPECT_TRUE(SetWakeOnWiFiAllowed(false, &e));
  EXPECT_FALSE(GetWakeOnWiFiAllowed());
  // When not allowed, SetWakeOnWiFiFeaturesEnabled should fail.
  e.Reset();
  EXPECT_FALSE(
      SetWakeOnWiFiFeaturesEnabled(kWakeOnWiFiFeaturesEnabledDarkConnect, &e));
  EXPECT_EQ(e.type(), Error::kIllegalOperation);
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledNone);

  // Turn on allowed property.
  EXPECT_TRUE(SetWakeOnWiFiAllowed(true, &e));
  EXPECT_TRUE(GetWakeOnWiFiAllowed());
  // When allowed, SetWakeOnWiFiFeaturesEnabled should work.
  EXPECT_TRUE(
      SetWakeOnWiFiFeaturesEnabled(kWakeOnWiFiFeaturesEnabledDarkConnect, &e));
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledDarkConnect);

  // Turn off allowed again. This should also flush enabled features.
  EXPECT_TRUE(SetWakeOnWiFiAllowed(false, &e));
  EXPECT_FALSE(GetWakeOnWiFiAllowed());
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledNone);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, SetWakeOnWiFiFeaturesEnabled) {
  const std::string bad_feature("blahblah");
  Error e;
  EnableWakeOnWiFiFeaturesDarkConnect();
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledDarkConnect);
  EXPECT_FALSE(
      SetWakeOnWiFiFeaturesEnabled(kWakeOnWiFiFeaturesEnabledDarkConnect, &e));
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledDarkConnect);

  EXPECT_FALSE(SetWakeOnWiFiFeaturesEnabled(bad_feature, &e));
  EXPECT_EQ(e.type(), Error::kInvalidArguments);
  EXPECT_STREQ(e.message().c_str(), "Invalid Wake on WiFi feature");
  EXPECT_STREQ(GetWakeOnWiFiFeaturesEnabled().c_str(),
               kWakeOnWiFiFeaturesEnabledDarkConnect);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       OnNoAutoConnectableServicesAfterScan_InDarkResume) {
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  EnableWakeOnWiFiFeaturesDarkConnect();
  SetInDarkResume(true);

  // Perform disconnect before suspend actions if we are in dark resume.
  GetWakeOnWiFiTriggers()->clear();
  StartDHCPLeaseRenewalTimer();
  StopWakeToScanTimer();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerSSID) !=
              GetWakeOnWiFiTriggers()->end());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       OnNoAutoConnectableServicesAfterScan_NotInDarkResume) {
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  EnableWakeOnWiFiFeaturesDarkConnect();
  SetInDarkResume(false);

  // If we are not in dark resume, do nothing.
  GetWakeOnWiFiTriggers()->clear();
  StartDHCPLeaseRenewalTimer();
  StopWakeToScanTimer();
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_TRUE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher,
       OnNoAutoConnectableServicesAfterScan_Retry) {
  std::vector<ByteString> allowed;
  AllowSSID(kSSIDBytes1, sizeof(kSSIDBytes1), &allowed);
  EnableWakeOnWiFiFeaturesDarkConnect();
  SetInDarkResume(true);
  SetDarkResumeScanRetriesLeft(1);

  // Perform a retry.
  EXPECT_EQ(1, GetDarkResumeScanRetriesLeft());
  EXPECT_CALL(*this, InitiateScanCallback(GetLastSSIDMatchFreqs()));
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_EQ(0, GetDarkResumeScanRetriesLeft());

  // Still no auto-connectable services after retry. No more retries, so perform
  // disconnect before suspend actions.
  GetWakeOnWiFiTriggers()->clear();
  StartDHCPLeaseRenewalTimer();
  StopWakeToScanTimer();
  EXPECT_CALL(*this, InitiateScanCallback(GetLastSSIDMatchFreqs())).Times(0);
  OnNoAutoConnectableServicesAfterScan(allowed);
  EXPECT_FALSE(DHCPLeaseRenewalTimerIsRunning());
  EXPECT_FALSE(WakeToScanTimerIsRunning());
  EXPECT_EQ(GetWakeOnWiFiTriggers()->size(), 1);
  EXPECT_TRUE(GetWakeOnWiFiTriggers()->find(WakeOnWiFi::kWakeTriggerSSID) !=
              GetWakeOnWiFiTriggers()->end());
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnWakeupReasonReceived_Unsupported) {
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  SetWiphyIndex(kWakeReasonNlMsg_WiphyIndex);

  SetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kWakeReasonUnsupportedNlMsg,
                       sizeof(kWakeReasonUnsupportedNlMsg));
  msg.InitFromPacket(&packet, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log,
              Log(_, _, HasSubstr("Wakeup reason: Not wake on WiFi related")));
  EXPECT_CALL(*this, RecordDarkResumeWakeReasonCallback(_)).Times(0);
  OnWakeupReasonReceived(msg);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());

  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnWakeupReasonReceived_Disconnect) {
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  SetWiphyIndex(kWakeReasonNlMsg_WiphyIndex);

  SetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kWakeReasonDisconnectNlMsg,
                       sizeof(kWakeReasonDisconnectNlMsg));
  msg.InitFromPacket(&packet, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(_, _, HasSubstr("Wakeup reason: Disconnect")));
  EXPECT_CALL(*this,
              RecordDarkResumeWakeReasonCallback(kWakeOnWiFiReasonDisconnect));
  OnWakeupReasonReceived(msg);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerDisconnect, GetLastWakeReason());

  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnWakeupReasonReceived_SSID) {
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(3);
  SetWiphyIndex(kWakeReasonNlMsg_WiphyIndex);

  SetWakeOnWiFiMessage msg;
  NetlinkPacket packet(kWakeReasonSSIDNlMsg, sizeof(kWakeReasonSSIDNlMsg));
  msg.InitFromPacket(&packet, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(_, _, HasSubstr("Wakeup reason: SSID")));
  EXPECT_CALL(*this, RecordDarkResumeWakeReasonCallback(kWakeOnWiFiReasonSSID));
  OnWakeupReasonReceived(msg);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerSSID, GetLastWakeReason());
  EXPECT_EQ(std::size(kSSID1FreqMatches), GetLastSSIDMatchFreqs().size());
  for (uint32_t freq : kSSID1FreqMatches) {
    EXPECT_TRUE(GetLastSSIDMatchFreqs().find(freq) !=
                GetLastSSIDMatchFreqs().end());
  }

  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, OnWakeupReasonReceived_Error) {
  ScopedMockLog log;
  ScopeLogger::GetInstance()->EnableScopesByName("wifi");
  ScopeLogger::GetInstance()->set_verbose_level(7);
  SetWiphyIndex(kWakeReasonNlMsg_WiphyIndex);

  // kWrongMessageTypeNlMsg has an nlmsg_type of 0x16, which is different from
  // the 0x13 (i.e. kNl80211FamilyId) that we expect in these unittests.
  GetWakeOnWiFiMessage msg0;
  NetlinkPacket packet0(kWrongMessageTypeNlMsg, sizeof(kWrongMessageTypeNlMsg));
  msg0.InitFromPacket(&packet0, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log, Log(_, _, HasSubstr("Not a NL80211 Message")));
  EXPECT_CALL(*this, RecordDarkResumeWakeReasonCallback(_)).Times(0);
  OnWakeupReasonReceived(msg0);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());

  // This message has command NL80211_CMD_GET_WOWLAN, not a
  // NL80211_CMD_SET_WOWLAN.
  GetWakeOnWiFiMessage msg1;
  NetlinkPacket packet1(kResponseNoWake, sizeof(kResponseNoWake));
  msg1.InitFromPacket(&packet1, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(log,
              Log(_, _, HasSubstr("Not a NL80211_CMD_SET_WOWLAN message")));
  EXPECT_CALL(*this, RecordDarkResumeWakeReasonCallback(_)).Times(0);
  OnWakeupReasonReceived(msg1);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());

  // Valid message, but wrong wiphy index.
  SetWiphyIndex(kWakeReasonNlMsg_WiphyIndex + 1);
  SetWakeOnWiFiMessage msg2;
  NetlinkPacket packet(kWakeReasonDisconnectNlMsg,
                       sizeof(kWakeReasonDisconnectNlMsg));
  msg2.InitFromPacket(&packet, GetWakeupReportMsgContext());
  EXPECT_CALL(log, Log(_, _, _)).Times(AnyNumber());
  EXPECT_CALL(
      log, Log(_, _, HasSubstr("Wakeup reason not meant for this interface")));
  EXPECT_CALL(*this, RecordDarkResumeWakeReasonCallback(_)).Times(0);
  OnWakeupReasonReceived(msg2);
  EXPECT_EQ(WakeOnWiFi::kWakeTriggerUnsupported, GetLastWakeReason());

  ScopeLogger::GetInstance()->EnableScopesByName("-wifi");
  ScopeLogger::GetInstance()->set_verbose_level(0);
}

TEST_F(WakeOnWiFiTestWithMockDispatcher, WakeOnWiFi_RemoveNetlinkHandler) {
  // WakeOnWifi is deleted when we go out of scope.
  EXPECT_CALL(netlink_manager_, RemoveBroadcastHandler(_)).Times(1);
}

}  // namespace shill
