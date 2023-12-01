// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_provider.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/format_macros.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/test/mock_callback.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/mock_control.h"
#include "shill/mock_event_dispatcher.h"
#include "shill/mock_manager.h"
#include "shill/mock_metrics.h"
#include "shill/mock_profile.h"
#include "shill/net/ieee80211.h"
#include "shill/net/mock_netlink_manager.h"
#include "shill/net/netlink_message_matchers.h"
#include "shill/net/netlink_packet.h"
#include "shill/net/nl80211_attribute.h"
#include "shill/net/nl80211_message.h"
#include "shill/store/fake_store.h"
#include "shill/supplicant/wpa_supplicant.h"
#include "shill/technology.h"
#include "shill/test_event_dispatcher.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/mock_local_device.h"
#include "shill/wifi/mock_passpoint_credentials.h"
#include "shill/wifi/mock_wake_on_wifi.h"
#include "shill/wifi/mock_wifi.h"
#include "shill/wifi/mock_wifi_phy.h"
#include "shill/wifi/mock_wifi_service.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_endpoint.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StartsWith;
using ::testing::StrictMock;
using ::testing::WithArg;

namespace shill {

const uint16_t kNl80211FamilyId = 0x13;

// Bytes representing an NL80211_CMD_NEW_WIPHY message reporting the WiFi
// capabilities of a phy with wiphy index |kNewWiphyNlMsg_WiphyIndex|.
const uint8_t kNewWiphyNlMsg[] = {
    0x68, 0x0c, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0xf6, 0x31, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x70, 0x68, 0x79, 0x30,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x3d, 0x00, 0x07, 0x00, 0x00, 0x00, 0x05, 0x00, 0x3e, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x3f, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x08, 0x00, 0x40, 0x00, 0xff, 0xff, 0xff, 0xff, 0x05, 0x00, 0x59, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2b, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x38, 0x00,
    0xd1, 0x08, 0x00, 0x00, 0x06, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x68, 0x00,
    0x04, 0x00, 0x8b, 0x00, 0x04, 0x00, 0x8c, 0x00, 0x18, 0x00, 0x39, 0x00,
    0x01, 0xac, 0x0f, 0x00, 0x05, 0xac, 0x0f, 0x00, 0x02, 0xac, 0x0f, 0x00,
    0x04, 0xac, 0x0f, 0x00, 0x06, 0xac, 0x0f, 0x00, 0x05, 0x00, 0x56, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x66, 0x00, 0x08, 0x00, 0x71, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x72, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x69, 0x00, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x6a, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x24, 0x00, 0x20, 0x00, 0x04, 0x00, 0x01, 0x00,
    0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x06, 0x00, 0x04, 0x00, 0x08, 0x00,
    0x04, 0x00, 0x09, 0x00, 0x50, 0x05, 0x16, 0x00, 0xf8, 0x01, 0x00, 0x00,
    0x14, 0x00, 0x03, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00,
    0xef, 0x11, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0x28, 0x01, 0x01, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x6c, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x71, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x76, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00,
    0x14, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00, 0x7b, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x80, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x85, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00,
    0x14, 0x00, 0x06, 0x00, 0x08, 0x00, 0x01, 0x00, 0x8a, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x07, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x8f, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x94, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00,
    0x14, 0x00, 0x09, 0x00, 0x08, 0x00, 0x01, 0x00, 0x99, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x6c, 0x07, 0x00, 0x00, 0x14, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x9e, 0x09, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xa3, 0x09, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x18, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xa8, 0x09, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0x6c, 0x07, 0x00, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xb4, 0x09, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0xa0, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x10, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x37, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x02, 0x00, 0x10, 0x00, 0x03, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x6e, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x04, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x78, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x07, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x09, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x68, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x0b, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x1c, 0x02, 0x00, 0x00, 0x54, 0x03, 0x01, 0x00,
    0x14, 0x00, 0x03, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00,
    0xef, 0x11, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x06, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc0, 0x02, 0x01, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x3c, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x50, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x14, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x64, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x14, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x78, 0x14, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x8c, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x20, 0x00, 0x05, 0x00, 0x08, 0x00, 0x01, 0x00, 0xa0, 0x14, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xb4, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x07, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xc8, 0x14, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x20, 0x00, 0x08, 0x00, 0x08, 0x00, 0x01, 0x00, 0x7c, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x09, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x90, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xa4, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x20, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x01, 0x00, 0xb8, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x0c, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xcc, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x01, 0x00,
    0xe0, 0x15, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x20, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x01, 0x00, 0xf4, 0x15, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x0f, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x08, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x10, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x1c, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x20, 0x00, 0x11, 0x00, 0x08, 0x00, 0x01, 0x00, 0x30, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x20, 0x00, 0x12, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x44, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x05, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x14, 0x00, 0x13, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x71, 0x16, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x1c, 0x00, 0x14, 0x00, 0x08, 0x00, 0x01, 0x00, 0x85, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x1c, 0x00, 0x15, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x99, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00,
    0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x1c, 0x00, 0x16, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xad, 0x16, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x06, 0x00, 0xd0, 0x07, 0x00, 0x00,
    0x1c, 0x00, 0x17, 0x00, 0x08, 0x00, 0x01, 0x00, 0xc1, 0x16, 0x00, 0x00,
    0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x04, 0x00, 0x08, 0x00, 0x06, 0x00,
    0xd0, 0x07, 0x00, 0x00, 0x64, 0x00, 0x02, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x78, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x03, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xb4, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x05, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x68, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x06, 0x00,
    0x08, 0x00, 0x01, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x07, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x1c, 0x02, 0x00, 0x00, 0xd4, 0x00, 0x32, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x0b, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00,
    0x13, 0x00, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x19, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x07, 0x00, 0x25, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
    0x26, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0x27, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x0a, 0x00, 0x28, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0b, 0x00,
    0x2b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x37, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x0d, 0x00, 0x39, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0e, 0x00,
    0x3b, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0f, 0x00, 0x43, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x10, 0x00, 0x31, 0x00, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00,
    0x41, 0x00, 0x00, 0x00, 0x08, 0x00, 0x12, 0x00, 0x42, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x13, 0x00, 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x14, 0x00,
    0x51, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x00, 0x54, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x16, 0x00, 0x57, 0x00, 0x00, 0x00, 0x08, 0x00, 0x17, 0x00,
    0x55, 0x00, 0x00, 0x00, 0x08, 0x00, 0x18, 0x00, 0x2d, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x19, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x08, 0x00, 0x1a, 0x00,
    0x30, 0x00, 0x00, 0x00, 0x08, 0x00, 0x6f, 0x00, 0x88, 0x13, 0x00, 0x00,
    0x04, 0x00, 0x6c, 0x00, 0xac, 0x03, 0x63, 0x00, 0x04, 0x00, 0x00, 0x00,
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
    0x06, 0x00, 0x65, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x14, 0x01, 0x64, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x06, 0x00, 0x65, 0x00,
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
    0x06, 0x00, 0x65, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x79, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x06, 0x00, 0x50, 0x00, 0x78, 0x00,
    0x4c, 0x00, 0x01, 0x00, 0x38, 0x00, 0x01, 0x00, 0x1c, 0x00, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
    0x04, 0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x04, 0x00, 0x08, 0x00,
    0x18, 0x00, 0x02, 0x00, 0x08, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x02, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0x09, 0x00,
    0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
    0x00, 0x08, 0x00, 0x00, 0x08, 0x00, 0x8f, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x1e, 0x00, 0x94, 0x00, 0x42, 0x08, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint32_t kNewWiphyNlMsg_WiphyIndex = 2;

// Bytes representing an NL80211_CMD_DEL_WIPHY message indicating the deletion
// of a phy with wiphy index |kNewWiphyNlMsg_WiphyIndex|.
const uint8_t kDelWiphyNlMsg[] = {
    0x30, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x00, 0x70, 0x68, 0x79, 0x32,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x2e, 0x00, 0x05, 0x00, 0x00, 0x00};

const uint32_t kDelWiphyNlMsg_WiphyIndex = 3;

const uint32_t kScanTriggerMsgWiphyIndex = 0;
const uint8_t kActiveScanTriggerNlMsg[] = {
    0x44, 0x01, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x21, 0x01, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x99, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x2d, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x2c, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x6c, 0x09, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
    0x71, 0x09, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x76, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x03, 0x00, 0x7b, 0x09, 0x00, 0x00, 0x08, 0x00, 0x04, 0x00,
    0x80, 0x09, 0x00, 0x00, 0x08, 0x00, 0x05, 0x00, 0x85, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x06, 0x00, 0x8a, 0x09, 0x00, 0x00, 0x08, 0x00, 0x07, 0x00,
    0x8f, 0x09, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x94, 0x09, 0x00, 0x00,
    0x08, 0x00, 0x09, 0x00, 0x99, 0x09, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
    0x9e, 0x09, 0x00, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x3c, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x0c, 0x00, 0x50, 0x14, 0x00, 0x00, 0x08, 0x00, 0x0d, 0x00,
    0x64, 0x14, 0x00, 0x00, 0x08, 0x00, 0x0e, 0x00, 0x78, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x0f, 0x00, 0x8c, 0x14, 0x00, 0x00, 0x08, 0x00, 0x10, 0x00,
    0xa0, 0x14, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00, 0xb4, 0x14, 0x00, 0x00,
    0x08, 0x00, 0x12, 0x00, 0xc8, 0x14, 0x00, 0x00, 0x08, 0x00, 0x13, 0x00,
    0x7c, 0x15, 0x00, 0x00, 0x08, 0x00, 0x14, 0x00, 0x90, 0x15, 0x00, 0x00,
    0x08, 0x00, 0x15, 0x00, 0xa4, 0x15, 0x00, 0x00, 0x08, 0x00, 0x16, 0x00,
    0xb8, 0x15, 0x00, 0x00, 0x08, 0x00, 0x17, 0x00, 0xcc, 0x15, 0x00, 0x00,
    0x08, 0x00, 0x18, 0x00, 0x1c, 0x16, 0x00, 0x00, 0x08, 0x00, 0x19, 0x00,
    0x30, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1a, 0x00, 0x44, 0x16, 0x00, 0x00,
    0x08, 0x00, 0x1b, 0x00, 0x58, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1c, 0x00,
    0x71, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x85, 0x16, 0x00, 0x00,
    0x08, 0x00, 0x1e, 0x00, 0x99, 0x16, 0x00, 0x00, 0x08, 0x00, 0x1f, 0x00,
    0xad, 0x16, 0x00, 0x00, 0x08, 0x00, 0x20, 0x00, 0xc1, 0x16, 0x00, 0x00};

class WiFiProviderTest : public testing::Test {
 public:
  explicit WiFiProviderTest(EventDispatcher* dispatcher = nullptr)
      : manager_(&control_, dispatcher ? dispatcher : &dispatcher_, &metrics_),
        provider_(&manager_),
        default_profile_(new NiceMock<MockProfile>(&manager_, "default")),
        user_profile_(new NiceMock<MockProfile>(&manager_, "user")),
        storage_entry_index_(0) {}

  ~WiFiProviderTest() override = default;

  void SetUp() override {
    EXPECT_CALL(*default_profile_, IsDefault()).WillRepeatedly(Return(true));
    EXPECT_CALL(*default_profile_, GetStorage())
        .WillRepeatedly(Return(&default_profile_storage_));
    EXPECT_CALL(*default_profile_, GetConstStorage())
        .WillRepeatedly(Return(&default_profile_storage_));

    EXPECT_CALL(*user_profile_, IsDefault()).WillRepeatedly(Return(false));
    EXPECT_CALL(*user_profile_, GetStorage())
        .WillRepeatedly(Return(&user_profile_storage_));
    EXPECT_CALL(*user_profile_, GetConstStorage())
        .WillRepeatedly(Return(&user_profile_storage_));

    // Default expectations for UMA metrics. Individual test cases
    // will override these, by adding later expectations.
    EXPECT_CALL(metrics_,
                SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, _))
        .Times(AnyNumber());
    EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, _))
        .Times(AnyNumber());
    EXPECT_CALL(
        metrics_,
        SendToUMA(
            Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
            _, _))
        .Times(AnyNumber());
    EXPECT_CALL(
        metrics_,
        SendToUMA(
            Metrics::
                kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
            _, _))
        .Times(AnyNumber());

    Nl80211Message::SetMessageType(kNl80211FamilyId);
    provider_.netlink_manager_ = &netlink_manager_;
  }

  // Used by mock invocations of RegisterService() to maintain the side-effect
  // of assigning a profile to |service|.
  void BindServiceToDefaultProfile(const ServiceRefPtr& service) {
    service->set_profile(default_profile_);
  }
  void BindServiceToUserProfile(const ServiceRefPtr& service) {
    service->set_profile(user_profile_);
  }

 protected:
  using MockWiFiServiceRefPtr = scoped_refptr<MockWiFiService>;

  void CreateServicesFromProfile(Profile* profile) {
    provider_.CreateServicesFromProfile(profile);
  }

  const std::vector<WiFiServiceRefPtr> GetServices() {
    return provider_.services_;
  }

  const WiFiProvider::EndpointServiceMap& GetServiceByEndpoint() {
    return provider_.service_by_endpoint_;
  }

  bool GetRunning() { return provider_.running_; }

  void RemoveCredentials(const PasspointCredentialsRefPtr& credentials) {
    provider_.RemoveCredentials(credentials);
  }

  void AddStringParameterToStorage(FakeStore* storage,
                                   const std::string& id,
                                   const std::string& key,
                                   const std::string& value) {
    storage->SetString(id, key, value);
  }

  // Adds service to profile's storage. But does not set profile on the Service.
  std::string AddServiceToProfileStorage(Profile* profile,
                                         const char* ssid,
                                         const char* mode,
                                         const char* security_class,
                                         bool is_hidden,
                                         bool provide_hidden) {
    std::string id = base::StringPrintf("entry_%d", storage_entry_index_);
    auto* profile_storage = static_cast<FakeStore*>(profile->GetStorage());
    AddStringParameterToStorage(profile_storage, id, WiFiService::kStorageType,
                                kTypeWifi);
    if (ssid) {
      const std::string ssid_string(ssid);
      const std::string hex_ssid(
          base::HexEncode(ssid_string.data(), ssid_string.size()));
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageSSID, hex_ssid);
    }
    if (mode) {
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageMode, mode);
    }
    if (security_class) {
      AddStringParameterToStorage(profile_storage, id,
                                  WiFiService::kStorageSecurityClass,
                                  security_class);
    }
    if (provide_hidden) {
      profile_storage->SetBool(id, kWifiHiddenSsid, is_hidden);
    } else {
      profile_storage->DeleteKey(id, kWifiHiddenSsid);
    }
    storage_entry_index_++;
    return id;
  }

  void SetServiceParameters(const char* ssid,
                            const char* mode,
                            const char* security_class,
                            bool is_hidden,
                            bool provide_hidden,
                            KeyValueStore* args) {
    args->Set<std::string>(kTypeProperty, kTypeWifi);
    if (ssid) {
      // TODO(pstew): When Chrome switches to using kWifiHexSsid primarily for
      // GetService and friends, we should switch to doing so here ourselves.
      args->Set<std::string>(kSSIDProperty, ssid);
    }
    if (mode) {
      args->Set<std::string>(kModeProperty, mode);
    }
    if (security_class) {
      args->Set<std::string>(kSecurityClassProperty, security_class);
    }
    if (provide_hidden) {
      args->Set<bool>(kWifiHiddenSsid, is_hidden);
    }
  }

  ServiceRefPtr CreateTemporaryService(const char* ssid,
                                       const char* mode,
                                       const char* security_class,
                                       bool is_hidden,
                                       bool provide_hidden,
                                       Error* error) {
    KeyValueStore args;
    SetServiceParameters(ssid, mode, security_class, is_hidden, provide_hidden,
                         &args);
    return provider_.CreateTemporaryService(args, error);
  }

  WiFiServiceRefPtr GetService(const char* ssid,
                               const char* mode,
                               const char* security_class,
                               bool is_hidden,
                               bool provide_hidden,
                               Error* error) {
    KeyValueStore args;
    SetServiceParameters(ssid, mode, security_class, is_hidden, provide_hidden,
                         &args);
    return provider_.GetWiFiService(args, error);
  }

  WiFiServiceRefPtr GetWiFiService(const KeyValueStore& args, Error* error) {
    return provider_.GetWiFiService(args, error);
  }

  WiFiServiceRefPtr FindService(const std::vector<uint8_t>& ssid,
                                const std::string& mode,
                                const std::string& security_class,
                                WiFiSecurity security = {}) {
    return provider_.FindService(ssid, mode, security_class, security);
  }
  WiFiEndpointRefPtr MakeOpenEndpoint(const std::string& ssid,
                                      const std::string& bssid,
                                      uint16_t frequency,
                                      int16_t signal_dbm) {
    return WiFiEndpoint::MakeOpenEndpoint(
        nullptr, nullptr, ssid, bssid,
        WPASupplicant::kNetworkModeInfrastructure, frequency, signal_dbm);
  }
  WiFiEndpointRefPtr Make8021xEndpoint(const std::string& ssid,
                                       const std::string& bssid,
                                       uint16_t frequency,
                                       int16_t signal_dbm) {
    WiFiEndpoint::SecurityFlags rsn_flags;
    rsn_flags.rsn_8021x = true;
    return WiFiEndpoint::MakeEndpoint(nullptr, nullptr, ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, rsn_flags);
  }
  WiFiEndpointRefPtr MakeEndpoint(
      const std::string& ssid,
      const std::string& bssid,
      uint16_t frequency,
      int16_t signal_dbm,
      const WiFiEndpoint::SecurityFlags& security_flags) {
    return WiFiEndpoint::MakeEndpoint(nullptr, nullptr, ssid, bssid,
                                      WPASupplicant::kNetworkModeInfrastructure,
                                      frequency, signal_dbm, security_flags);
  }
  MockWiFiServiceRefPtr AddMockService(const std::vector<uint8_t>& ssid,
                                       const std::string& mode,
                                       const std::string& security_class,
                                       bool hidden_ssid) {
    MockWiFiServiceRefPtr service =
        new MockWiFiService(&manager_, &provider_, ssid, mode, security_class,
                            WiFiSecurity(), hidden_ssid);
    provider_.services_.push_back(service);
    return service;
  }
  MockWiFiPhy* AddMockPhy(uint32_t phy_index) {
    std::unique_ptr<MockWiFiPhy> mock_phy_unique =
        std::make_unique<MockWiFiPhy>(phy_index);
    MockWiFiPhy* mock_phy_raw = mock_phy_unique.get();
    provider_.wifi_phys_[phy_index] = std::move(mock_phy_unique);
    return mock_phy_raw;
  }

  void AddEndpointToService(WiFiServiceRefPtr service,
                            const WiFiEndpointConstRefPtr& endpoint) {
    provider_.service_by_endpoint_[endpoint.get()] = service;
  }
  std::string AddCredentialsToProfileStorage(
      Profile* profile,
      const std::vector<std::string>& domains,
      const std::string& realm,
      const std::vector<uint64_t>& home_ois,
      const std::vector<uint64_t>& required_home_ois,
      const std::vector<uint64_t>& roaming_consortia,
      bool metered_override,
      const std::string& app_package_name,
      const std::string& friendly_name,
      uint64_t expiration_time) {
    std::string id = base::StringPrintf("entry_%d", storage_entry_index_);
    auto* profile_storage = static_cast<FakeStore*>(profile->GetStorage());
    PasspointCredentialsRefPtr creds = new PasspointCredentials(
        id, domains, realm, home_ois, required_home_ois, roaming_consortia,
        metered_override, app_package_name, friendly_name, expiration_time);
    creds->Save(profile_storage);
    storage_entry_index_++;
    return id;
  }
  PasspointCredentialsRefPtr GetCredentials(const std::string& id) {
    if (provider_.credentials_by_id_.find(id) ==
        provider_.credentials_by_id_.end()) {
      return nullptr;
    }
    return provider_.credentials_by_id_[id];
  }
  std::string AddCredentialsToProvider(
      const std::vector<std::string>& domains,
      const std::string& realm,
      const std::vector<uint64_t>& home_ois,
      const std::vector<uint64_t>& required_home_ois,
      const std::vector<uint64_t>& roaming_consortia,
      bool metered_override,
      const std::string& app_package_name,
      const std::string& friendly_name,
      uint64_t expiration_time) {
    std::string id = PasspointCredentials::GenerateIdentifier();
    PasspointCredentialsRefPtr creds = new PasspointCredentials(
        id, domains, realm, home_ois, required_home_ois, roaming_consortia,
        metered_override, app_package_name, friendly_name, expiration_time);
    provider_.AddCredentials(creds);
    return id;
  }

  void OnNewWiphy(const Nl80211Message& nl80211_message) {
    provider_.OnNewWiphy(nl80211_message);
  }

  void HandleNetlinkBroadcast(const shill::NetlinkMessage& message) {
    provider_.HandleNetlinkBroadcast(message);
  }

  void RegisterDeviceToPhy(WiFiConstRefPtr device, uint32_t phy_index) {
    provider_.RegisterDeviceToPhy(device, phy_index);
  }

  void DeregisterDeviceFromPhy(WiFiConstRefPtr device, uint32_t phy_index) {
    provider_.DeregisterDeviceFromPhy(device, phy_index);
  }

  const WiFiPhy* GetPhyAtIndex(uint32_t phy_index) {
    return provider_.GetPhyAtIndex(phy_index);
  }

  StrictMock<base::MockRepeatingCallback<void(LocalDevice::DeviceEvent,
                                              const LocalDevice*)>>
      cb;

  scoped_refptr<MockLocalDevice> CreateLocalDevice(
      LocalDevice::IfaceType type, const std::string& link_name) {
    scoped_refptr<MockLocalDevice> dev = new NiceMock<MockLocalDevice>(
        &manager_, type, link_name, "00:00:00:00:00:00", 0, cb.Get());
    return dev;
  }

  MockControl control_;
  EventDispatcherForTest dispatcher_;
  MockMetrics metrics_;
  MockNetlinkManager netlink_manager_;
  StrictMock<MockManager> manager_;
  WiFiProvider provider_;
  scoped_refptr<MockProfile> default_profile_;
  scoped_refptr<MockProfile> user_profile_;
  FakeStore default_profile_storage_;
  FakeStore user_profile_storage_;
  int storage_entry_index_;  // shared across profiles
};

class WiFiProviderTest2 : public WiFiProviderTest {
 public:
  WiFiProviderTest2() : WiFiProviderTest(&dispatcher_) {}

 protected:
  MockEventDispatcher dispatcher_;
};

MATCHER_P(RefPtrMatch, ref, "") {
  return ref.get() == arg.get();
}

MATCHER_P(IsZeroTime, is_zero, "") {
  return is_zero == arg.is_zero();
}

TEST_F(WiFiProviderTest, Start) {
  // Doesn't do anything really.  Just testing for no crash.
  EXPECT_TRUE(GetServices().empty());
  EXPECT_FALSE(GetRunning());
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, NL80211_CMD_GET_WIPHY), _, _, _));
  EXPECT_CALL(netlink_manager_,
              SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                NetlinkManager::kEventTypeConfig));
  EXPECT_CALL(netlink_manager_,
              SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                NetlinkManager::kEventTypeScan));
  EXPECT_CALL(netlink_manager_,
              SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                NetlinkManager::kEventTypeRegulatory));
  EXPECT_CALL(netlink_manager_,
              SubscribeToEvents(Nl80211Message::kMessageTypeString,
                                NetlinkManager::kEventTypeMlme));
  provider_.Start();
  EXPECT_TRUE(GetServices().empty());
  EXPECT_TRUE(GetRunning());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
  EXPECT_FALSE(provider_.disable_vht());
}

TEST_F(WiFiProviderTest, Stop) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityClassNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityClassNone, false);
  WiFiEndpointRefPtr endpoint = MakeOpenEndpoint("", "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint);

  EXPECT_EQ(2, GetServices().size());
  EXPECT_FALSE(GetServiceByEndpoint().empty());
  EXPECT_CALL(*service0, ResetWiFi()).Times(1);
  EXPECT_CALL(*service1, ResetWiFi()).Times(1);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service1))).Times(1);
  provider_.Stop();
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(GetServices().empty());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileWithNoGroups) {
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingSSID) {
  AddServiceToProfileStorage(default_profile_.get(), nullptr, kModeManaged,
                             kSecurityClassNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptySSID) {
  AddServiceToProfileStorage(default_profile_.get(), "", kModeManaged,
                             kSecurityClassNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingMode) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", nullptr,
                             kSecurityClassNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptyMode) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", "",
                             kSecurityClassNone, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingSecurity) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             nullptr, false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileEmptySecurity) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged, "",
                             false, true);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileMissingHidden) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityClassNone, false, false);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileSingle) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityClassNone, false, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1))
      .Times(2);
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  const WiFiServiceRefPtr service = GetServices().front();
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityClassNone));

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
  EXPECT_EQ(1, GetServices().size());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileHiddenButConnected) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityClassNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, RequestScan(_, _)).Times(0);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1))
      .Times(2);
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
}

TEST_F(WiFiProviderTest, CreateServicesFromProfileHiddenNotConnected) {
  std::string kSSID("foo");
  AddServiceToProfileStorage(default_profile_.get(), kSSID.c_str(),
                             kModeManaged, kSecurityClassNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(false));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(1);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1))
      .Times(2);
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0))
      .Times(2);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).Times(0);
  EXPECT_CALL(manager_, RequestScan(_, _)).Times(0);
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  CreateServicesFromProfile(default_profile_.get());
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileNonWiFi) {
  const std::string kEntryName("name");
  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, kEntryName, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(),
              StartsWith("Unspecified or invalid network type"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingSSID) {
  std::string entry_name =
      AddServiceToProfileStorage(default_profile_.get(), nullptr, kModeManaged,
                                 kSecurityClassNone, false, true);
  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Unspecified or invalid SSID"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingMode) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", "", kSecurityClassNone, false, true);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Network mode not specified"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingSecurity) {
  std::string entry_name = AddServiceToProfileStorage(
      default_profile_.get(), "foo", kModeManaged, "", false, true);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(),
              StartsWith("Unspecified or invalid security class"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfileMissingHidden) {
  std::string entry_name =
      AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                                 kSecurityClassNone, false, false);

  Error error;
  EXPECT_EQ(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_THAT(error.message(), StartsWith("Hidden SSID not specified"));
}

TEST_F(WiFiProviderTest, CreateTemporaryServiceFromProfile) {
  std::string entry_name =
      AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                                 kSecurityClassNone, false, true);

  Error error;
  EXPECT_NE(nullptr, provider_.CreateTemporaryServiceFromProfile(
                         default_profile_, entry_name, &error));
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, CreateTwoServices) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityClassNone, false, true);
  AddServiceToProfileStorage(default_profile_.get(), "bar", kModeManaged,
                             kSecurityClassNone, true, true);
  EXPECT_CALL(manager_, RegisterService(_))
      .Times(2)
      .WillRepeatedly(
          Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(Technology(Technology::kWiFi)))
      .WillOnce(Return(true));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(0);
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 2));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_EQ(2, GetServices().size());
}

TEST_F(WiFiProviderTest, ServiceSourceStats) {
  AddServiceToProfileStorage(default_profile_.get(), "foo", kModeManaged,
                             kSecurityClassPsk, false /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToDefaultProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  // Processing default profile does not generate UMA metrics.
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          _, _))
      .Times(0);
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat, _,
          _))
      .Times(0);
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, _))
      .Times(0);
  EXPECT_CALL(metrics_,
              SendEnumToUMA(Metrics::kMetricHiddenSSIDEverConnected, _, _))
      .Times(0);
  CreateServicesFromProfile(default_profile_.get());
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(&metrics_);

  AddServiceToProfileStorage(user_profile_.get(), "bar", kModeManaged,
                             kSecurityClassPsk, false /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToUserProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  // Processing user profile generates metrics for both, default profile,
  // and user profile.
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "none", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "wep", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "psk", 1));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "802_1x", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "none", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "wep", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "psk", 1));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "802_1x", 0));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 2));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, 0));
  EXPECT_CALL(metrics_,
              SendBoolToUMA(Metrics::kMetricHiddenSSIDEverConnected, _))
      .Times(0);
  CreateServicesFromProfile(user_profile_.get());
}

TEST_F(WiFiProviderTest, ServiceSourceStatsHiddenSSID) {
  AddServiceToProfileStorage(user_profile_.get(), "foo", kModeManaged,
                             kSecurityClassPsk, true /* is_hidden */,
                             true /* provide_hidden */);
  EXPECT_CALL(manager_, RegisterService(_))
      .WillOnce(Invoke(this, &WiFiProviderTest::BindServiceToUserProfile));
  EXPECT_CALL(manager_, IsServiceEphemeral(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, IsTechnologyConnected(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, RequestScan(kTypeWifi, _)).Times(1);
  // Processing user profile generates metrics for both, default profile,
  // and user profile.
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "none", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "wep", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "psk", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedSystemWiFiNetworkCountBySecurityModeFormat,
          "802_1x", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "none", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "wep", 0));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "psk", 1));
  EXPECT_CALL(
      metrics_,
      SendToUMA(
          Metrics::kMetricRememberedUserWiFiNetworkCountBySecurityModeFormat,
          "802_1x", 0));
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricRememberedWiFiNetworkCount, 1));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricPasspointNetworkCount, 0));
  EXPECT_CALL(metrics_, SendToUMA(Metrics::kMetricHiddenSSIDNetworkCount, 1));
  EXPECT_CALL(metrics_,
              SendBoolToUMA(Metrics::kMetricHiddenSSIDEverConnected, false));
  CreateServicesFromProfile(user_profile_.get());
}

TEST_F(WiFiProviderTest, GetServiceEmptyMode) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "", kSecurityClassNone, false, false, &error).get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, GetServiceNoMode) {
  Error error;
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_TRUE(
      GetService("foo", nullptr, kSecurityClassNone, false, false, &error)
          .get());
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, GetServiceBadMode) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "BogoMesh", kSecurityClassNone, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid service mode", error.message());
}

TEST_F(WiFiProviderTest, GetServiceAdhocNotSupported) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", "adhoc", kSecurityClassNone, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid service mode", error.message());
}

TEST_F(WiFiProviderTest, GetServiceNoSSID) {
  Error error;
  EXPECT_FALSE(GetService(nullptr, kModeManaged, kSecurityClassNone, false,
                          false, &error)
                   .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("must specify SSID", error.message());
}

TEST_F(WiFiProviderTest, GetServiceEmptySSID) {
  Error error;
  EXPECT_FALSE(
      GetService("", kModeManaged, kSecurityClassNone, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidNetworkName, error.type());
  EXPECT_EQ("SSID is too short", error.message());
}

TEST_F(WiFiProviderTest, GetServiceLongSSID) {
  Error error;
  std::string ssid(IEEE_80211::kMaxSSIDLen + 1, '0');
  EXPECT_FALSE(GetService(ssid.c_str(), kModeManaged, kSecurityClassNone, false,
                          false, &error)
                   .get());
  EXPECT_EQ(Error::kInvalidNetworkName, error.type());
  EXPECT_EQ("SSID is too long", error.message());
}

TEST_F(WiFiProviderTest, GetServiceJustLongEnoughSSID) {
  Error error;
  std::string ssid(IEEE_80211::kMaxSSIDLen, '0');
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_TRUE(GetService(ssid.c_str(), kModeManaged, kSecurityClassNone, false,
                         false, &error)
                  .get());
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, GetServiceBadSecurityClass) {
  Error error;
  EXPECT_FALSE(
      GetService("foo", kModeManaged, kSecurityWpa2, false, false, &error)
          .get());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
  EXPECT_EQ("invalid security class", error.message());
}

TEST_F(WiFiProviderTest, GetServiceMinimal) {
  Error error;
  const std::string kSSID("foo");
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  WiFiServiceRefPtr service =
      GetService(kSSID.c_str(), kModeManaged, nullptr, false, false, &error);
  EXPECT_NE(nullptr, service);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());

  // These two should be set to their default values if not specified.
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityClassNone));
  EXPECT_TRUE(service->hidden_ssid());
}

TEST_F(WiFiProviderTest, GetServiceFullySpecified) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  const std::string kSSID("bar");
  Error error;
  WiFiServiceRefPtr service0 = GetService(
      kSSID.c_str(), kModeManaged, kSecurityClassPsk, false, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service0->ssid().begin(),
                                 service0->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service0->mode());
  EXPECT_TRUE(service0->IsSecurityMatch(kSecurityClassPsk));
  EXPECT_FALSE(service0->hidden_ssid());

  // Getting the same service parameters (even with a different hidden
  // parameter) should return the same service.
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  WiFiServiceRefPtr service1 = GetService(
      kSSID.c_str(), kModeManaged, kSecurityClassPsk, true, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(service0, service1);
  EXPECT_EQ(1, GetServices().size());

  // Getting the same ssid with different other parameters should return
  // a different service.
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  WiFiServiceRefPtr service2 = GetService(
      kSSID.c_str(), kModeManaged, kSecurityClassNone, true, true, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_NE(service0, service2);
  EXPECT_EQ(2, GetServices().size());
}

TEST_F(WiFiProviderTest, GetServiceByHexSsid) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  const std::string kSSID("bar");
  const std::string kHexSsid(base::HexEncode(kSSID.c_str(), kSSID.length()));

  KeyValueStore args;
  SetServiceParameters(nullptr, nullptr, kSecurityClassPsk, false, true, &args);
  args.Set<std::string>(kWifiHexSsid, kHexSsid);

  Error error;
  WiFiServiceRefPtr service = GetWiFiService(args, &error);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_TRUE(error.IsSuccess());
  const std::string service_ssid(service->ssid().begin(),
                                 service->ssid().end());
  EXPECT_EQ(kSSID, service_ssid);
  EXPECT_EQ(kModeManaged, service->mode());
  EXPECT_TRUE(service->IsSecurityMatch(kSecurityClassPsk));
  EXPECT_FALSE(service->hidden_ssid());

  // While here, make sure FindSimilarService also supports kWifiHexSsid.
  Error find_error;
  ServiceRefPtr find_service = provider_.FindSimilarService(args, &find_error);
  EXPECT_TRUE(find_error.IsSuccess());
  EXPECT_EQ(service, find_service);
}

TEST_F(WiFiProviderTest, GetServiceWithSecurityProperty) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  args.Set<std::string>(kSecurityProperty, kSecurityWpa2);
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  service = GetWiFiService(args, &error);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(WiFiProviderTest, GetServiceBogusSecurityClass) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  args.Set<std::string>(kSecurityClassProperty, "rot-47");
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  service = GetWiFiService(args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, GetServiceNonSecurityClass) {
  const std::string kSSID("bar");
  KeyValueStore args;
  args.Set<std::string>(kTypeProperty, kTypeWifi);
  args.Set<std::string>(kSSIDProperty, kSSID);
  // Using a non-class as a class should be rejected.
  args.Set<std::string>(kSecurityClassProperty, kSecurityWpa2);
  args.Set<bool>(kWifiHiddenSsid, false);

  Error error;
  WiFiServiceRefPtr service;
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  service = GetWiFiService(args, &error);
  EXPECT_FALSE(error.IsSuccess());
  EXPECT_EQ(Error::kInvalidArguments, error.type());
}

TEST_F(WiFiProviderTest, FindSimilarService) {
  // Since CreateTemporyService uses exactly the same validation as
  // GetService, don't bother with testing invalid parameters.
  const std::string kSSID("foo");
  KeyValueStore args;
  SetServiceParameters(kSSID.c_str(), kModeManaged, kSecurityClassNone, true,
                       true, &args);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error get_service_error;
  WiFiServiceRefPtr service = GetWiFiService(args, &get_service_error);
  EXPECT_EQ(1, GetServices().size());

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(service, find_service);
    EXPECT_TRUE(error.IsSuccess());
  }

  args.Set<bool>(kWifiHiddenSsid, false);

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(service, find_service);
    EXPECT_TRUE(error.IsSuccess());
  }

  args.Set<std::string>(kSecurityClassProperty, kSecurityClassPsk);

  {
    Error error;
    ServiceRefPtr find_service = provider_.FindSimilarService(args, &error);
    EXPECT_EQ(nullptr, find_service);
    EXPECT_EQ(Error::kNotFound, error.type());
  }
}

TEST_F(WiFiProviderTest, CreateTemporaryService) {
  // Since CreateTemporyService uses exactly the same validation as
  // GetService, don't bother with testing invalid parameters.
  const std::string kSSID("foo");
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error error;
  WiFiServiceRefPtr service0 = GetService(
      kSSID.c_str(), kModeManaged, kSecurityClassNone, true, true, &error);
  EXPECT_EQ(1, GetServices().size());
  Mock::VerifyAndClearExpectations(&manager_);

  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  ServiceRefPtr service1 = CreateTemporaryService(
      kSSID.c_str(), kModeManaged, kSecurityClassNone, true, true, &error);

  // Test that a new service was created, but not registered with the
  // manager or added to the provider's service list.
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(service0 != service1);
  EXPECT_TRUE(service1->HasOneRef());
}

TEST_F(WiFiProviderTest, FindServicePSK) {
  const std::string kSSID("an_ssid");
  Error error;
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  KeyValueStore args;
  auto psk_class = kSecurityClassPsk;
  SetServiceParameters(kSSID.c_str(), kModeManaged, psk_class, false, false,
                       &args);
  WiFiServiceRefPtr service = GetWiFiService(args, &error);
  ASSERT_NE(nullptr, service);
  const std::vector<uint8_t> ssid_bytes(kSSID.begin(), kSSID.end());
  WiFiServiceRefPtr wpa_service(
      FindService(ssid_bytes, kModeManaged, psk_class, WiFiSecurity::kWpa));
  EXPECT_EQ(service, wpa_service);
  WiFiServiceRefPtr rsn_service(
      FindService(ssid_bytes, kModeManaged, psk_class, WiFiSecurity::kWpa2));
  EXPECT_EQ(service, rsn_service);
  WiFiServiceRefPtr wpa3_service(
      FindService(ssid_bytes, kModeManaged, psk_class, WiFiSecurity::kWpa3));
  EXPECT_EQ(service, wpa3_service);
  WiFiServiceRefPtr psk_service(
      FindService(ssid_bytes, kModeManaged, psk_class));
  EXPECT_EQ(service, psk_service);
  WiFiServiceRefPtr wep_service(FindService(
      ssid_bytes, kModeManaged, kSecurityClassWep, WiFiSecurity::kWep));
  EXPECT_EQ(nullptr, wep_service);
}

TEST_F(WiFiProviderTest, FindServiceForEndpoint) {
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  Error error;
  const std::string kSSID("an_ssid");
  WiFiServiceRefPtr service = GetService(
      kSSID.c_str(), kModeManaged, kSecurityClassNone, false, true, &error);
  ASSERT_NE(nullptr, service);
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(kSSID, "00:00:00:00:00:00", 0, 0);
  WiFiServiceRefPtr endpoint_service =
      provider_.FindServiceForEndpoint(endpoint);
  // Just because a matching service exists, we shouldn't necessarily have
  // it returned.  We will test that this function returns the correct
  // service if the endpoint is added below.
  EXPECT_EQ(nullptr, endpoint_service);
}

TEST_F(WiFiProviderTest, OnEndpointAdded) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  EXPECT_FALSE(FindService(ssid0_bytes, kModeManaged, kSecurityClassNone));
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityClassNone));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(1, GetServiceByEndpoint().size());
  WiFiServiceRefPtr endpoint_service =
      provider_.FindServiceForEndpoint(endpoint0);
  EXPECT_EQ(service0, endpoint_service);

  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:01", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  EXPECT_FALSE(FindService(ssid1_bytes, kModeManaged, kSecurityClassNone));
  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint(ssid1, "00:00:00:00:00:02", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint2);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(
      FindService(ssid1_bytes, kModeManaged, kSecurityClassNone));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_TRUE(service1 != service0);
}

TEST_F(WiFiProviderTest, OnEndpointAddedWithSecurity) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  EXPECT_FALSE(FindService(ssid0_bytes, kModeManaged, kSecurityClassNone));
  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint0 =
      MakeEndpoint(ssid0, "00:00:00:00:00:00", 0, 0, rsn_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());
  WiFiServiceRefPtr service0(FindService(
      ssid0_bytes, kModeManaged, kSecurityClassPsk, WiFiSecurity::kWpa2));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(WiFiSecurity::kWpa2, service0->security());

  WiFiEndpoint::SecurityFlags wpa_flags;
  wpa_flags.wpa_psk = true;
  WiFiEndpointRefPtr endpoint1 =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, wpa_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());
  EXPECT_EQ(WiFiSecurity::kWpaWpa2, service0->security());

  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  EXPECT_FALSE(FindService(ssid1_bytes, kModeManaged, kSecurityClassNone));
  WiFiEndpointRefPtr endpoint2 =
      MakeEndpoint(ssid1, "00:00:00:00:00:02", 0, 0, wpa_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint2);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(
      FindService(ssid1_bytes, kModeManaged, kSecurityClassPsk));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_EQ(WiFiSecurity::kWpa, service1->security());
  EXPECT_TRUE(service1 != service0);
}

TEST_F(WiFiProviderTest, OnEndpointAddedMultiSecurity) {
  // Multiple security modes with the same SSID.
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());

  WiFiEndpoint::SecurityFlags rsn_flags;
  rsn_flags.rsn_psk = true;
  WiFiEndpointRefPtr endpoint0 =
      MakeEndpoint(ssid0, "00:00:00:00:00:00", 0, 0, rsn_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(1, GetServices().size());

  WiFiServiceRefPtr service0(FindService(
      ssid0_bytes, kModeManaged, kSecurityClassPsk, WiFiSecurity::kWpa2));
  EXPECT_NE(nullptr, service0);
  EXPECT_TRUE(service0->HasEndpoints());
  EXPECT_EQ(WiFiSecurity::kWpa2, service0->security());

  WiFiEndpoint::SecurityFlags none_flags;
  WiFiEndpointRefPtr endpoint1 =
      MakeEndpoint(ssid0, "00:00:00:00:00:01", 0, 0, none_flags);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  EXPECT_EQ(2, GetServices().size());

  WiFiServiceRefPtr service1(FindService(
      ssid0_bytes, kModeManaged, kSecurityClassNone, WiFiSecurity::kNone));
  EXPECT_NE(nullptr, service1);
  EXPECT_TRUE(service1->HasEndpoints());
  EXPECT_EQ(WiFiSecurity::kNone, service1->security());
  EXPECT_EQ(WiFiSecurity::kWpa2, service0->security());
}

TEST_F(WiFiProviderTest, OnEndpointAddedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointAdded should have no effect.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(_)).Times(0);
  provider_.OnEndpointAdded(endpoint);
  EXPECT_TRUE(GetServices().empty());
}

TEST_F(WiFiProviderTest, OnEndpointAddedToMockService) {
  // The previous test allowed the provider to create its own "real"
  // WiFiServices, which hides some of what we can test with mock
  // services.  Re-do an add-endpoint operation by seeding the provider
  // with a mock service.
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityClassNone, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurityClassNone, false);
  EXPECT_EQ(service0,
            FindService(ssid0_bytes, kModeManaged, kSecurityClassNone));
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service1, AddEndpoint(_)).Times(0);
  provider_.OnEndpointAdded(endpoint0);
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());

  WiFiEndpointRefPtr endpoint1 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:01", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(RefPtrMatch(endpoint1))).Times(1);
  EXPECT_CALL(*service1, AddEndpoint(_)).Times(0);
  provider_.OnEndpointAdded(endpoint1);
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());

  WiFiEndpointRefPtr endpoint2 =
      MakeOpenEndpoint(ssid1, "00:00:00:00:00:02", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service1))).Times(1);
  EXPECT_CALL(*service0, AddEndpoint(_)).Times(0);
  EXPECT_CALL(*service1, AddEndpoint(RefPtrMatch(endpoint2))).Times(1);
  provider_.OnEndpointAdded(endpoint2);
}

TEST_F(WiFiProviderTest, OnEndpointRemoved) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityClassNone, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurityClassNone, false);
  EXPECT_EQ(2, GetServices().size());

  // Remove the last endpoint of a non-remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service1, RemoveEndpoint(_)).Times(0);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, ResetWiFi()).Times(1);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(0);
  EXPECT_CALL(manager_, DeregisterService(RefPtrMatch(service0))).Times(1);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  Mock::VerifyAndClearExpectations(service1.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_EQ(service1, GetServices().front());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedButHasEndpoints) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityClassNone, false);
  EXPECT_EQ(1, GetServices().size());

  // Remove an endpoint of a non-remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(true));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, ResetWiFi()).Times(0);
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedButIsRemembered) {
  provider_.Start();
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityClassNone, false);
  EXPECT_EQ(1, GetServices().size());

  // Remove the last endpoint of a remembered service.
  WiFiEndpointRefPtr endpoint0 =
      MakeOpenEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  AddEndpointToService(service0, endpoint0);
  EXPECT_EQ(1, GetServiceByEndpoint().size());

  EXPECT_CALL(*service0, RemoveEndpoint(RefPtrMatch(endpoint0))).Times(1);
  EXPECT_CALL(*service0, HasEndpoints()).WillRepeatedly(Return(false));
  EXPECT_CALL(*service0, IsRemembered()).WillRepeatedly(Return(true));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0))).Times(1);
  EXPECT_CALL(*service0, ResetWiFi()).Times(0);
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);
  provider_.OnEndpointRemoved(endpoint0);
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(&manager_);
  Mock::VerifyAndClearExpectations(service0.get());
  EXPECT_EQ(1, GetServices().size());
  EXPECT_TRUE(GetServiceByEndpoint().empty());
}

TEST_F(WiFiProviderTest, OnEndpointRemovedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointRemoved should not
  // cause a crash even if a service matching the endpoint does not exist.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  provider_.OnEndpointRemoved(endpoint);
}

TEST_F(WiFiProviderTest, OnEndpointUpdated) {
  provider_.Start();

  // Create an endpoint and associate it with a mock service.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);

  const std::vector<uint8_t> ssid_bytes(ssid.begin(), ssid.end());
  MockWiFiServiceRefPtr open_service =
      AddMockService(ssid_bytes, kModeManaged, kSecurityClassNone, false);
  EXPECT_CALL(*open_service, AddEndpoint(RefPtrMatch(endpoint)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(open_service)));
  provider_.OnEndpointAdded(endpoint);
  Mock::VerifyAndClearExpectations(open_service.get());

  // WiFiProvider is running and endpoint matches this service.
  EXPECT_CALL(*open_service, NotifyEndpointUpdated(RefPtrMatch(endpoint)));
  EXPECT_CALL(*open_service, AddEndpoint(_)).Times(0);
  provider_.OnEndpointUpdated(endpoint);
  Mock::VerifyAndClearExpectations(open_service.get());

  // If the endpoint is changed in a way that causes it to match a different
  // service, the provider should transfer the endpoint from one service to
  // the other.
  MockWiFiServiceRefPtr rsn_service =
      AddMockService(ssid_bytes, kModeManaged, kSecurityClassPsk, false);
  EXPECT_CALL(*open_service, RemoveEndpoint(RefPtrMatch(endpoint)));
  // We are playing out a scenario where the open service is not removed
  // since it still claims to have more endpoints remaining.
  EXPECT_CALL(*open_service, HasEndpoints()).WillRepeatedly(Return(true));
  EXPECT_CALL(*rsn_service, AddEndpoint(RefPtrMatch(endpoint)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(open_service)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(rsn_service)));
  endpoint->set_security_mode(WiFiSecurity::kWpa2);
  provider_.OnEndpointUpdated(endpoint);
}

TEST_F(WiFiProviderTest, OnEndpointUpdatedWhileStopped) {
  // If we don't call provider_.Start(), OnEndpointUpdated should not
  // cause a crash even if a service matching the endpoint does not exist.
  const std::string ssid("an_ssid");
  WiFiEndpointRefPtr endpoint =
      MakeOpenEndpoint(ssid, "00:00:00:00:00:00", 0, 0);
  provider_.OnEndpointUpdated(endpoint);
}

TEST_F(WiFiProviderTest, OnServiceUnloaded) {
  // This function should never unregister services itself -- the Manager
  // will automatically deregister the service if OnServiceUnloaded()
  // returns true (via WiFiService::Unload()).
  EXPECT_CALL(manager_, DeregisterService(_)).Times(0);

  MockWiFiServiceRefPtr service = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityClassNone, false);
  EXPECT_EQ(1, GetServices().size());
  EXPECT_CALL(*service, HasEndpoints()).WillOnce(Return(true));
  EXPECT_CALL(*service, ResetWiFi()).Times(0);
  EXPECT_FALSE(provider_.OnServiceUnloaded(service, nullptr));
  EXPECT_EQ(1, GetServices().size());
  Mock::VerifyAndClearExpectations(service.get());

  EXPECT_CALL(*service, HasEndpoints()).WillOnce(Return(false));
  EXPECT_CALL(*service, ResetWiFi()).Times(1);
  EXPECT_TRUE(provider_.OnServiceUnloaded(service, nullptr));
  // Verify now, so it's clear that this happened as a result of the call
  // above, and not anything in the destructor(s).
  Mock::VerifyAndClearExpectations(service.get());
  EXPECT_TRUE(GetServices().empty());

  Mock::VerifyAndClearExpectations(&manager_);
}

TEST_F(WiFiProviderTest, GetHiddenSSIDList) {
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());
  const std::vector<uint8_t> ssid0(1, '0');
  AddMockService(ssid0, kModeManaged, kSecurityClassNone, false);
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());

  const std::vector<uint8_t> ssid1(1, '1');
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1, kModeManaged, kSecurityClassNone, true);
  EXPECT_CALL(*service1, IsRemembered()).WillRepeatedly(Return(false));
  EXPECT_TRUE(provider_.GetHiddenSSIDList().empty());

  const std::vector<uint8_t> ssid2(1, '2');
  MockWiFiServiceRefPtr service2 =
      AddMockService(ssid2, kModeManaged, kSecurityClassNone, true);
  EXPECT_CALL(*service2, IsRemembered()).WillRepeatedly(Return(true));
  ByteArrays ssid_list = provider_.GetHiddenSSIDList();

  EXPECT_EQ(1, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);

  const std::vector<uint8_t> ssid3(1, '3');
  MockWiFiServiceRefPtr service3 =
      AddMockService(ssid3, kModeManaged, kSecurityClassNone, false);
  EXPECT_CALL(*service3, IsRemembered()).WillRepeatedly(Return(true));

  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(1, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);

  const std::vector<uint8_t> ssid4(1, '4');
  MockWiFiServiceRefPtr service4 =
      AddMockService(ssid4, kModeManaged, kSecurityClassNone, true);
  EXPECT_CALL(*service4, IsRemembered()).WillRepeatedly(Return(true));

  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(2, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid2);
  EXPECT_TRUE(ssid_list[1] == ssid4);

  service4->source_ = Service::ONCSource::kONCSourceUserPolicy;
  const std::vector<uint8_t> ssid5(1, '5');
  MockWiFiServiceRefPtr service5 =
      AddMockService(ssid5, kModeManaged, kSecurityClassNone, true);
  EXPECT_CALL(*service5, IsRemembered()).WillRepeatedly(Return(true));
  service5->source_ = Service::ONCSource::kONCSourceDevicePolicy;
  ssid_list = provider_.GetHiddenSSIDList();
  EXPECT_EQ(3, ssid_list.size());
  EXPECT_TRUE(ssid_list[0] == ssid4);
  EXPECT_TRUE(ssid_list[1] == ssid5);
  EXPECT_TRUE(ssid_list[2] == ssid2);
}

TEST_F(WiFiProviderTest, ReportAutoConnectableServices) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityClassNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityClassNone, false);
  service0->EnableAndRetainAutoConnect();
  service0->SetConnectable(true);
  service1->EnableAndRetainAutoConnect();
  service1->SetConnectable(true);

  EXPECT_CALL(*service0, IsAutoConnectable(_))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*service1, IsAutoConnectable(_)).WillRepeatedly(Return(false));

  // With 1 auto connectable service.
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricWifiAutoConnectableServices, 1));
  provider_.ReportAutoConnectableServices();

  // With no auto connectable service.
  EXPECT_CALL(metrics_,
              SendToUMA(Metrics::kMetricWifiAutoConnectableServices, _))
      .Times(0);
  provider_.ReportAutoConnectableServices();
}

TEST_F(WiFiProviderTest, NumAutoConnectableServices) {
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityClassNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityClassNone, false);
  service0->EnableAndRetainAutoConnect();
  service0->SetConnectable(true);
  service1->EnableAndRetainAutoConnect();
  service1->SetConnectable(true);

  EXPECT_CALL(*service0, IsAutoConnectable(_))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*service1, IsAutoConnectable(_)).WillRepeatedly(Return(true));

  // 2 auto-connectable services.
  EXPECT_EQ(2, provider_.NumAutoConnectableServices());

  // 1 auto-connectable service.
  EXPECT_EQ(1, provider_.NumAutoConnectableServices());
}

TEST_F(WiFiProviderTest, ResetAutoConnectCooldownTime) {
  provider_.Start();
  MockWiFiServiceRefPtr service0 = AddMockService(
      std::vector<uint8_t>(1, '0'), kModeManaged, kSecurityClassNone, false);
  MockWiFiServiceRefPtr service1 = AddMockService(
      std::vector<uint8_t>(1, '1'), kModeManaged, kSecurityClassNone, false);

  EXPECT_CALL(*service0, ResetAutoConnectCooldownTime).Times(1);
  EXPECT_CALL(*service1, ResetAutoConnectCooldownTime).Times(1);
  provider_.ResetServicesAutoConnectCooldownTime();
}

TEST_F(WiFiProviderTest, GetSsidsConfiguredForAutoConnect) {
  std::vector<uint8_t> ssid0(3, '0');
  std::vector<uint8_t> ssid1(5, '1');
  ByteString ssid0_bytes(ssid0);
  ByteString ssid1_bytes(ssid1);
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0, kModeManaged, kSecurityClassNone, false);
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1, kModeManaged, kSecurityClassNone, false);
  // 2 services configured for auto-connect.
  service0->SetAutoConnect(true);
  service1->SetAutoConnect(true);
  std::vector<ByteString> service_list_0 =
      provider_.GetSsidsConfiguredForAutoConnect();
  EXPECT_EQ(2, service_list_0.size());
  EXPECT_TRUE(ssid0_bytes.Equals(service_list_0[0]));
  EXPECT_TRUE(ssid1_bytes.Equals(service_list_0[1]));

  // 1 service configured for auto-connect.
  service0->SetAutoConnect(false);
  service1->SetAutoConnect(true);
  std::vector<ByteString> service_list_1 =
      provider_.GetSsidsConfiguredForAutoConnect();
  EXPECT_EQ(1, service_list_1.size());
  EXPECT_TRUE(ssid1_bytes.Equals(service_list_1[0]));
}

TEST_F(WiFiProviderTest, LoadCredentialsFromProfileAndCheckContent) {
  std::vector<std::string> domains{"sp-blue.com", "sp-green.com"};
  std::string realm("sp-blue.com");
  std::vector<uint64_t> home_ois{0x123456789, 0x65798731, 0x1};
  std::vector<uint64_t> required_home_ois{0x111222333444, 0x99887744};
  std::vector<uint64_t> roaming_consortia{0x1010101010, 0x2020202020};
  std::string app_name("com.sp-blue.app");
  std::string friendly_name("My Provider");
  uint64_t expiration_time = 1906869600000;

  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(2)
      .WillRepeatedly(Return(nullptr));

  // Add credentials to the user profile.
  std::string id = AddCredentialsToProfileStorage(
      user_profile_.get(), domains, realm, home_ois, required_home_ois,
      roaming_consortia,
      /*metered_override=*/true, app_name, friendly_name, expiration_time);
  provider_.LoadCredentialsFromProfile(user_profile_.get());

  // Check the credentials are correct.
  PasspointCredentialsRefPtr creds = GetCredentials(id);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(id, creds->id());
  EXPECT_EQ(user_profile_.get(), creds->profile());
  EXPECT_EQ(domains, creds->domains());
  EXPECT_EQ(realm, creds->realm());
  EXPECT_EQ(home_ois, creds->home_ois());
  EXPECT_EQ(required_home_ois, creds->required_home_ois());
  EXPECT_EQ(roaming_consortia, creds->roaming_consortia());
  EXPECT_TRUE(creds->metered_override());
  EXPECT_EQ(app_name, creds->android_package_name());

  // Remove it
  provider_.UnloadCredentialsFromProfile(user_profile_.get());
  EXPECT_TRUE(!GetCredentials(id));
}

TEST_F(WiFiProviderTest, LoadUnloadCredentialsFromProfile) {
  std::vector<std::string> domains{"sp-blue.com", "sp-green.com"};
  std::string realm("sp-blue.com");
  std::vector<uint64_t> ois{0x123456789, 0x65798731, 0x1};
  std::string app_name("com.sp-blue.app");
  std::string friendly_name("My Provider");
  uint64_t expiration_time = 1906869600000;

  // We expect: two adds and two removes
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(4)
      .WillRepeatedly(Return(nullptr));

  // Add credentials to both Profiles.
  std::string id_default = AddCredentialsToProfileStorage(
      default_profile_.get(), domains, realm,
      /*home_ois=*/ois,
      /*required_home_ois=*/ois,
      /*roaming_consortia=*/ois,
      /*metered_override=*/true, app_name, friendly_name, expiration_time);
  provider_.LoadCredentialsFromProfile(default_profile_.get());
  std::string id_user = AddCredentialsToProfileStorage(
      user_profile_.get(), domains, realm,
      /*home_ois=*/ois,
      /*required_home_ois=*/ois,
      /*roaming_consortia=*/ois,
      /*metered_override=*/true, app_name, friendly_name, expiration_time);
  provider_.LoadCredentialsFromProfile(user_profile_.get());

  // Check both credentials are available
  PasspointCredentialsRefPtr creds;
  creds = GetCredentials(id_default);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(default_profile_.get(), creds->profile());
  creds = GetCredentials(id_user);
  EXPECT_TRUE(creds != nullptr);
  EXPECT_EQ(user_profile_.get(), creds->profile());

  // Remove it
  provider_.UnloadCredentialsFromProfile(user_profile_.get());
  EXPECT_TRUE(GetCredentials(id_user) == nullptr);
  EXPECT_TRUE(GetCredentials(id_default) != nullptr);
  provider_.UnloadCredentialsFromProfile(default_profile_.get());
  EXPECT_TRUE(GetCredentials(id_default) == nullptr);
}

TEST_F(WiFiProviderTest, AddRemoveCredentials) {
  std::vector<std::string> domains{"sp-red.com", "sp-blue.com"};
  std::string realm("sp-red.com");
  std::vector<uint64_t> ois{0x1122334455, 0x97643165, 0x30};
  std::string app_name("com.sp-red.app");
  std::string friendly_name("My Red Provider");
  uint64_t expiration_time = 1906869610000;

  // We expect two calls, one during add, one during remove.
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .Times(2)
      .WillRepeatedly(Return(nullptr));

  // Add a set of credentials.
  std::string id =
      AddCredentialsToProvider(domains, realm, ois, ois, ois, false, app_name,
                               friendly_name, expiration_time);
  PasspointCredentialsRefPtr creds = GetCredentials(id);
  EXPECT_TRUE(creds != nullptr);

  // Check it is present
  std::vector<PasspointCredentialsRefPtr> list = provider_.GetCredentials();
  EXPECT_EQ(1, list.size());
  EXPECT_EQ(creds, list[0]);

  // Remove the set of credentials
  list.clear();
  RemoveCredentials(creds);
  list = provider_.GetCredentials();
  EXPECT_EQ(0, list.size());
}

TEST_F(WiFiProviderTest, ForgetCredentials) {
  provider_.Start();

  // Add a set of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  creds0->SetProfile(user_profile_);
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  provider_.AddCredentials(creds0);

  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  MockWiFiServiceRefPtr service0 =
      AddMockService(ssid0_bytes, kModeManaged, kSecurityClass8021x, false);
  const std::string ssid1("another_ssid");
  const std::vector<uint8_t> ssid1_bytes(ssid1.begin(), ssid1.end());
  MockWiFiServiceRefPtr service1 =
      AddMockService(ssid1_bytes, kModeManaged, kSecurityClass8021x, false);

  // Report endpoints
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  WiFiEndpointRefPtr endpoint1 =
      Make8021xEndpoint(ssid1, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service0)));
  EXPECT_CALL(manager_, UpdateService(RefPtrMatch(service1)));
  provider_.OnEndpointAdded(endpoint0);
  provider_.OnEndpointAdded(endpoint1);

  // Report two matches that will fill the two services
  std::vector<WiFiProvider::PasspointMatch> matches{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kHome},
      {creds0, endpoint1, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(2);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(2);
  provider_.OnPasspointCredentialsMatches(matches);

  // Ensure both services are removed.
  EXPECT_CALL(manager_, RemoveService(RefPtrMatch(service0)));
  EXPECT_CALL(manager_, RemoveService(RefPtrMatch(service1)));
  provider_.ForgetCredentials(creds0);
}

TEST_F(WiFiProviderTest, SimpleCredentialsMatchesOverride) {
  provider_.Start();

  // Add few sets of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  PasspointCredentialsRefPtr creds1 = new MockPasspointCredentials("creds1");
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  creds0->SetProfile(user_profile_);
  provider_.AddCredentials(creds0);
  creds1->SetProfile(user_profile_);
  provider_.AddCredentials(creds1);

  // Provide some scan results
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);

  // Report a match
  std::vector<WiFiProvider::PasspointMatch> match{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(1);
  provider_.OnPasspointCredentialsMatches(match);

  // The best match for endpoint0 is cred0 with "Roaming" priority.
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityClass8021x));
  EXPECT_EQ(WiFiProvider::MatchPriority::kRoaming, service0->match_priority());
  EXPECT_EQ(creds0, service0->parent_credentials());

  // Report a match that overrides the previous one.
  std::vector<WiFiProvider::PasspointMatch> better_match{
      {creds1, endpoint0, WiFiProvider::MatchPriority::kHome}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  EXPECT_CALL(manager_, MoveServiceToProfile(_, _)).Times(1);
  provider_.OnPasspointCredentialsMatches(better_match);

  service0 = FindService(ssid0_bytes, kModeManaged, kSecurityClass8021x);
  EXPECT_EQ(WiFiProvider::MatchPriority::kHome, service0->match_priority());
  EXPECT_EQ(creds1, service0->parent_credentials());
}

TEST_F(WiFiProviderTest, MultipleCredentialsMatches) {
  provider_.Start();

  // Add few sets of credentials
  PasspointCredentialsRefPtr creds0 = new MockPasspointCredentials("creds0");
  PasspointCredentialsRefPtr creds1 = new MockPasspointCredentials("creds1");
  EXPECT_CALL(manager_, GetEnabledDeviceWithTechnology(_))
      .WillRepeatedly(Return(nullptr));
  provider_.AddCredentials(creds0);
  provider_.AddCredentials(creds1);

  // Provide some scan results
  const std::string ssid0("an_ssid");
  const std::vector<uint8_t> ssid0_bytes(ssid0.begin(), ssid0.end());
  WiFiEndpointRefPtr endpoint0 =
      Make8021xEndpoint(ssid0, "00:00:00:00:00:00", 0, 0);
  EXPECT_CALL(manager_, RegisterService(_)).Times(1);
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnEndpointAdded(endpoint0);

  // Report matches
  std::vector<WiFiProvider::PasspointMatch> matches{
      {creds0, endpoint0, WiFiProvider::MatchPriority::kHome},
      {creds1, endpoint0, WiFiProvider::MatchPriority::kRoaming}};
  EXPECT_CALL(manager_, UpdateService(_)).Times(1);
  provider_.OnPasspointCredentialsMatches(matches);

  // The best match for endpoint0 is cred0 because of the "Home" priority.
  WiFiServiceRefPtr service0(
      FindService(ssid0_bytes, kModeManaged, kSecurityClass8021x));
  EXPECT_EQ(WiFiProvider::MatchPriority::kHome, service0->match_priority());
  EXPECT_EQ(creds0, service0->parent_credentials());
}

TEST_F(WiFiProviderTest, RegisterAndDeregisterWiFiDevice) {
  const uint32_t phy_index = 0;
  scoped_refptr<MockWiFi> device = new NiceMock<MockWiFi>(
      &manager_, "null0", "addr0", 0, phy_index, new MockWakeOnWiFi());

  // Registering a device to a non-existent phy should result in a failed CHECK.
  EXPECT_DEATH(RegisterDeviceToPhy(device, phy_index),
               "Tried to register WiFi device");

  // Register device to existing phy.
  MockWiFiPhy* phy = AddMockPhy(phy_index);
  RegisterDeviceToPhy(device, phy_index);
  EXPECT_EQ(GetPhyAtIndex(phy_index), phy);

  // The phy should still exist after deregistering the device.
  DeregisterDeviceFromPhy(device, phy_index);
  EXPECT_EQ(GetPhyAtIndex(phy_index), phy);
}

TEST_F(WiFiProviderTest, OnNewWiphy_WrongMessage) {
  TriggerScanMessage msg;
  NetlinkPacket packet(kActiveScanTriggerNlMsg,
                       sizeof(kActiveScanTriggerNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  MockWiFiPhy* phy = AddMockPhy(kScanTriggerMsgWiphyIndex);

  EXPECT_CALL(*phy, OnNewWiphy(_)).Times(0);
  OnNewWiphy(msg);
}

TEST_F(WiFiProviderTest, OnNewWiphy_NoIndex) {
  NewWiphyMessage msg;
  // Do not initialize the message so that it has no NL80211_ATTR_WIPHY.
  MockWiFiPhy* phy = AddMockPhy(kNewWiphyNlMsg_WiphyIndex);

  EXPECT_CALL(*phy, OnNewWiphy(_)).Times(0);
  OnNewWiphy(msg);
}

TEST_F(WiFiProviderTest, OnNewWiphy_WithPhy) {
  NewWiphyMessage msg;
  MockWiFiPhy* phy = AddMockPhy(kNewWiphyNlMsg_WiphyIndex);
  NetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  // OnNewWiphy message should be forwarded to the existing phy.
  EXPECT_CALL(*phy, OnNewWiphy(_));
  OnNewWiphy(msg);
}

TEST_F(WiFiProviderTest, OnNewWiphy_WithoutPhy) {
  NewWiphyMessage msg;
  NetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  EXPECT_EQ(nullptr, GetPhyAtIndex(kNewWiphyNlMsg_WiphyIndex));
  // We should create a new WiFiPhy object when we get a NewWiphy message for a
  // new phy_index.
  OnNewWiphy(msg);
  EXPECT_NE(nullptr, GetPhyAtIndex(kNewWiphyNlMsg_WiphyIndex));
}

TEST_F(WiFiProviderTest, NetLinkBroadcast_NewPhy) {
  NewWiphyMessage msg;
  NetlinkPacket packet(kNewWiphyNlMsg, sizeof(kNewWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  EXPECT_EQ(nullptr, GetPhyAtIndex(kNewWiphyNlMsg_WiphyIndex));
  // We should create a new WiFiPhy object when we get a NewWiphy broadcast for
  // a new phy_index.
  HandleNetlinkBroadcast(msg);
  EXPECT_NE(nullptr, GetPhyAtIndex(kNewWiphyNlMsg_WiphyIndex));
}

TEST_F(WiFiProviderTest, NetLinkBroadcast_DeletePresentPhy) {
  DelWiphyMessage msg;
  AddMockPhy(kDelWiphyNlMsg_WiphyIndex);
  NetlinkPacket packet(kDelWiphyNlMsg, sizeof(kDelWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  EXPECT_NE(nullptr, GetPhyAtIndex(kDelWiphyNlMsg_WiphyIndex));
  // The phy should be deleted.
  HandleNetlinkBroadcast(msg);
  EXPECT_EQ(nullptr, GetPhyAtIndex(kDelWiphyNlMsg_WiphyIndex));
}

TEST_F(WiFiProviderTest, NetLinkBroadcast_DeleteAbsentPhy) {
  DelWiphyMessage msg;
  NetlinkPacket packet(kDelWiphyNlMsg, sizeof(kDelWiphyNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  EXPECT_EQ(nullptr, GetPhyAtIndex(kDelWiphyNlMsg_WiphyIndex));
  HandleNetlinkBroadcast(msg);
  EXPECT_EQ(nullptr, GetPhyAtIndex(kDelWiphyNlMsg_WiphyIndex));
}

TEST_F(WiFiProviderTest, NetLinkBroadcast_IncludesPresentPhy) {
  TriggerScanMessage msg;
  NetlinkPacket packet(kActiveScanTriggerNlMsg,
                       sizeof(kActiveScanTriggerNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());
  AddMockPhy(kScanTriggerMsgWiphyIndex);

  // We have a WiFiPhy object at the phy index in msg, so we do not expect an
  // NL80211_CMD_GET_WIPHY to be triggered.
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, NL80211_CMD_GET_WIPHY), _, _, _))
      .Times(0);
  HandleNetlinkBroadcast(msg);
}

TEST_F(WiFiProviderTest, NetLinkBroadcast_IncludesAbsentPhy) {
  TriggerScanMessage msg;
  NetlinkPacket packet(kActiveScanTriggerNlMsg,
                       sizeof(kActiveScanTriggerNlMsg));
  msg.InitFromPacket(&packet, NetlinkMessage::MessageContext());

  // We do not have a WiFiPhy object at the phy index in msg, so we expect an
  // NL80211_CMD_GET_WIPHY to be triggered.
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, NL80211_CMD_GET_WIPHY), _, _, _));
  HandleNetlinkBroadcast(msg);
}

TEST_F(WiFiProviderTest, RemoveNetlinkHandler) {
  provider_.Start();
  EXPECT_CALL(netlink_manager_, RemoveBroadcastHandler(_));
  provider_.Stop();
}

TEST_F(WiFiProviderTest, RegisterWiFiLocalDevice) {
  const uint32_t phy_index = 0;
  std::string link_name = "testlocaldevice";

  AddMockPhy(phy_index);
  scoped_refptr<MockLocalDevice> device =
      CreateLocalDevice(LocalDevice::IfaceType::kAP, link_name);
  provider_.RegisterLocalDevice(device);
  EXPECT_EQ(provider_.local_devices_[link_name], device);

  // Register same device again should be a no-op.
  provider_.RegisterLocalDevice(device);
  EXPECT_EQ(provider_.local_devices_[link_name], device);
  EXPECT_EQ(provider_.local_devices_.count(link_name), 1);
}

TEST_F(WiFiProviderTest, DeregisterWiFiLocalDevice) {
  const uint32_t phy_index = 0;
  std::string link_name = "testlocaldevice";
  AddMockPhy(phy_index);
  scoped_refptr<MockLocalDevice> device =
      CreateLocalDevice(LocalDevice::IfaceType::kAP, link_name);
  provider_.RegisterLocalDevice(device);

  provider_.DeregisterLocalDevice(device);
  EXPECT_EQ(provider_.local_devices_.count(link_name), 0);

  // Deregister a non-existent  device should be a no-op.
  provider_.DeregisterLocalDevice(device);
  EXPECT_EQ(provider_.local_devices_.count(link_name), 0);
}

TEST_F(WiFiProviderTest, GetUniqueLocalDeviceName) {
  const uint32_t phy_index = 0;
  std::string iface_prefix = "testlocaldevice";
  AddMockPhy(phy_index);

  std::string link_name0 = provider_.GetUniqueLocalDeviceName(iface_prefix);
  scoped_refptr<MockLocalDevice> device0 =
      CreateLocalDevice(LocalDevice::IfaceType::kAP, link_name0);
  provider_.RegisterLocalDevice(device0);

  // Use a new interface name different from the registered one.
  std::string link_name1 = provider_.GetUniqueLocalDeviceName(iface_prefix);
  EXPECT_NE(link_name0, link_name1);
  scoped_refptr<MockLocalDevice> device1 =
      CreateLocalDevice(LocalDevice::IfaceType::kAP, link_name1);
  provider_.RegisterLocalDevice(device1);

  // Reuse the first available interface name after device is deregistered.
  provider_.DeregisterLocalDevice(device0);
  std::string link_name = provider_.GetUniqueLocalDeviceName(iface_prefix);
  EXPECT_EQ(link_name0, link_name);
}

TEST_F(WiFiProviderTest2, UpdatePhyInfo_NoChange) {
  // With region domains set correctly the notification callback should be
  // called immediately signaling no change ('false' as argument).
  provider_.NotifyCountry("US", RegulatorySource::kCurrent);
  provider_.NotifyCountry("US", RegulatorySource::kCellular);
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _)).Times(0);
  int times_called = 0;
  provider_.UpdateRegAndPhyInfo(
      base::BindOnce([](int& cnt) { ++cnt; }, std::ref(times_called)));
  EXPECT_EQ(times_called, 1);
}

TEST_F(WiFiProviderTest2, UpdatePhyInfo_Timeout) {
  // With different region domains we expect to request domain and phy update,
  // however our request might not get a reply, so we should time out and run
  // the callback.
  provider_.NotifyCountry("00", RegulatorySource::kCurrent);
  provider_.NotifyCountry("US", RegulatorySource::kCellular);
  int times_called = 0;
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(
                  IsNl80211Command(kNl80211FamilyId, NL80211_CMD_REQ_SET_REG),
                  _, _, _));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, _))
      .WillOnce(WithArg<1>(Invoke([&](auto cb) { std::move(cb).Run(); })));
  provider_.UpdateRegAndPhyInfo(
      base::BindOnce([](int& cnt) { ++cnt; }, std::ref(times_called)));
  EXPECT_EQ(times_called, 1);
}

TEST_F(WiFiProviderTest2, UpdatePhyInfo_Success) {
  // With different region domains we expect to request domain and phy update.
  provider_.NotifyCountry("00", RegulatorySource::kCurrent);
  provider_.NotifyCountry("US", RegulatorySource::kCellular);
  int times_called = 0;
  EXPECT_CALL(netlink_manager_,
              SendNl80211Message(
                  IsNl80211Command(kNl80211FamilyId, NL80211_CMD_REQ_SET_REG),
                  _, _, _));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, IsZeroTime(false))).Times(1);
  provider_.UpdateRegAndPhyInfo(
      base::BindOnce([](int& cnt) { ++cnt; }, std::ref(times_called)));

  // Now simulate reception of region change, expect phy dump and simulate
  // reception of "Done" message (signaling the end of "split messages" dump).
  Mock::VerifyAndClearExpectations(&dispatcher_);
  EXPECT_CALL(
      netlink_manager_,
      SendNl80211Message(
          IsNl80211Command(kNl80211FamilyId, NL80211_CMD_GET_WIPHY), _, _, _));
  EXPECT_CALL(dispatcher_, PostDelayedTask(_, _, IsZeroTime(true)))
      .WillOnce(WithArg<1>(Invoke([](auto cb) { std::move(cb).Run(); })));
  provider_.RegionChanged("US");
  provider_.OnGetPhyInfoAuxMessage(NetlinkManager::kDone, nullptr);
  EXPECT_EQ(times_called, 1);
  EXPECT_TRUE(provider_.phy_update_timeout_cb_.IsCancelled());
}

}  // namespace shill
