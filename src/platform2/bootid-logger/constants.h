// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTID_LOGGER_CONSTANTS_H_
#define BOOTID_LOGGER_CONSTANTS_H_

constexpr size_t kBootIdLength = 32u;

constexpr char kBootEntryPrefix[] = "boot_id: ";
constexpr char kBootEntrySeverity[] = "INFO";

// Length of timestamp (eg. "2020-12-12T00:00:00.000000Z". The value is 27.
constexpr size_t kTimestampLength = 27u;
// Length of timestamp (eg. "2020-12-12T00:00:00.000000+00:00". The value is 32.
constexpr size_t kLocalTimeTimestampLength = 32u;
// Length of severity string "INFO". The value is 4.
constexpr size_t kSeverityLength = sizeof(kBootEntrySeverity) - 1;
// Length of prefix string "boot_id: ", including a space. The value is 9.
constexpr size_t kPrefixLength = sizeof(kBootEntryPrefix) - 1;

// Offsets for UTC timestamp boot entries.
constexpr size_t kBootEntrySeverityOffset = kTimestampLength + 1;
constexpr size_t kBootEntryPrefixOffset =
    kBootEntrySeverityOffset + kSeverityLength + 1;
constexpr size_t kBootEntryBootIdOffset =
    kBootEntryPrefixOffset + kPrefixLength;
constexpr size_t kBootEntryLength = kBootEntryBootIdOffset + kBootIdLength;

// Offsets for local timezone timestamp boot entries.
constexpr size_t kBootEntryLocalTimeSeverityOffset =
    kLocalTimeTimestampLength + 1;
constexpr size_t kBootEntryLocalTimeMessageOffset =
    kBootEntryLocalTimeSeverityOffset + kSeverityLength + 1;
constexpr size_t kBootEntryLocalTimeBootIdOffset =
    kBootEntryLocalTimeMessageOffset + kPrefixLength;
constexpr size_t kBootEntryLocalTimeLength =
    kBootEntryLocalTimeBootIdOffset + kBootIdLength;

#endif  // BOOTID_LOGGER_CONSTANTS_H_
