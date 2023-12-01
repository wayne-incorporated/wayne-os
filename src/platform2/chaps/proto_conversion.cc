// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/proto_conversion.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <string>

#include <base/check.h>
#include <base/logging.h>
#include <google/protobuf/message_lite.h>

namespace {

bool ProtoToVersion(const chaps::Version& proto, CK_VERSION* out_version) {
  DCHECK(out_version);
  if (!proto.has_major() || !proto.has_minor())
    return false;

  out_version->major = static_cast<CK_BYTE>(proto.major());
  out_version->minor = static_cast<CK_BYTE>(proto.minor());
  return true;
}

void VersionToProto(const CK_VERSION* version, chaps::Version* proto) {
  DCHECK(version);
  DCHECK(proto);
  proto->set_major(static_cast<uint32_t>(version->major));
  proto->set_minor(static_cast<uint32_t>(version->minor));
}

void ZeroAndCopy(CK_BYTE* dest, const std::string& src, size_t buf_size) {
  memset(dest, 0, buf_size);
  memcpy(dest, src.c_str(), std::min(buf_size, src.size()));
}

std::string CopyToString(const CK_BYTE* src, size_t buf_size) {
  return std::string(reinterpret_cast<const char*>(src), buf_size);
}

}  // namespace

namespace chaps {

bool ProtoToMechanismInfo(const MechanismInfo& proto,
                          CK_MECHANISM_INFO* out_info) {
  DCHECK(out_info);
  if (!proto.has_min_key_size() || !proto.has_max_key_size() ||
      !proto.has_flags())
    return false;

  out_info->ulMinKeySize = static_cast<CK_ULONG>(proto.min_key_size());
  out_info->ulMaxKeySize = static_cast<CK_ULONG>(proto.max_key_size());
  out_info->flags = static_cast<CK_FLAGS>(proto.flags());
  return true;
}

MechanismInfo MechanismInfoToProto(const CK_MECHANISM_INFO* info) {
  DCHECK(info);
  MechanismInfo proto;
  proto.set_min_key_size(static_cast<uint64_t>(info->ulMinKeySize));
  proto.set_max_key_size(static_cast<uint64_t>(info->ulMaxKeySize));
  proto.set_flags(static_cast<uint64_t>(info->flags));
  return proto;
}

bool ProtoToSessionInfo(const SessionInfo& proto, CK_SESSION_INFO* out_info) {
  DCHECK(out_info);
  if (!proto.has_slot_id() || !proto.has_state() || !proto.has_flags() ||
      !proto.has_device_error())
    return false;

  out_info->slotID = static_cast<CK_SLOT_ID>(proto.slot_id());
  out_info->state = static_cast<CK_STATE>(proto.state());
  out_info->flags = static_cast<CK_FLAGS>(proto.flags());
  out_info->ulDeviceError = static_cast<CK_ULONG>(proto.device_error());
  return true;
}

SessionInfo SessionInfoToProto(const CK_SESSION_INFO* info) {
  DCHECK(info);
  SessionInfo proto;
  proto.set_slot_id(static_cast<uint64_t>(info->slotID));
  proto.set_state(static_cast<uint64_t>(info->state));
  proto.set_flags(static_cast<uint64_t>(info->flags));
  proto.set_device_error(static_cast<uint64_t>(info->ulDeviceError));
  return proto;
}

bool ProtoToSlotInfo(const SlotInfo& proto, CK_SLOT_INFO* out_info) {
  DCHECK(out_info);
  if (!proto.has_slot_description() || !proto.has_manufacturer_id() ||
      !proto.has_flags() || !proto.has_hardware_version() ||
      !proto.has_firmware_version())
    return false;

  ZeroAndCopy(out_info->slotDescription, proto.slot_description(), 64);
  ZeroAndCopy(out_info->manufacturerID, proto.manufacturer_id(), 32);
  out_info->flags = static_cast<CK_FLAGS>(proto.flags());

  if (!ProtoToVersion(proto.hardware_version(), &out_info->hardwareVersion) ||
      !ProtoToVersion(proto.firmware_version(), &out_info->firmwareVersion))
    return false;

  return true;
}

SlotInfo SlotInfoToProto(const CK_SLOT_INFO* info) {
  DCHECK(info);
  SlotInfo proto;
  proto.set_slot_description(CopyToString(info->slotDescription, 64));
  proto.set_manufacturer_id(CopyToString(info->manufacturerID, 32));
  proto.set_flags(static_cast<uint64_t>(info->flags));
  VersionToProto(&info->hardwareVersion, proto.mutable_hardware_version());
  VersionToProto(&info->firmwareVersion, proto.mutable_firmware_version());
  return proto;
}

bool ProtoToTokenInfo(const TokenInfo& proto, CK_TOKEN_INFO* out_info) {
  DCHECK(out_info);
  if (!proto.has_label() || !proto.has_manufacturer_id() ||
      !proto.has_model() || !proto.has_serial_number() || !proto.has_flags() ||
      !proto.has_max_session_count() || !proto.has_session_count() ||
      !proto.has_max_session_count_rw() || !proto.has_session_count_rw() ||
      !proto.has_max_pin_len() || !proto.has_min_pin_len() ||
      !proto.has_total_public_memory() || !proto.has_free_public_memory() ||
      !proto.has_total_private_memory() || !proto.has_free_private_memory() ||
      !proto.has_hardware_version() || !proto.has_firmware_version())
    return false;

  ZeroAndCopy(out_info->label, proto.label(), 32);
  ZeroAndCopy(out_info->manufacturerID, proto.manufacturer_id(), 32);
  ZeroAndCopy(out_info->model, proto.model(), 16);
  ZeroAndCopy(out_info->serialNumber, proto.serial_number(), 16);
  out_info->flags = static_cast<CK_FLAGS>(proto.flags());
  out_info->ulMaxSessionCount =
      static_cast<CK_ULONG>(proto.max_session_count());
  out_info->ulSessionCount = static_cast<CK_ULONG>(proto.session_count());
  out_info->ulMaxRwSessionCount =
      static_cast<CK_ULONG>(proto.max_session_count_rw());
  out_info->ulRwSessionCount = static_cast<CK_ULONG>(proto.session_count_rw());
  out_info->ulMaxPinLen = static_cast<CK_ULONG>(proto.max_pin_len());
  out_info->ulMinPinLen = static_cast<CK_ULONG>(proto.min_pin_len());
  out_info->ulTotalPublicMemory =
      static_cast<CK_ULONG>(proto.total_public_memory());
  out_info->ulFreePublicMemory =
      static_cast<CK_ULONG>(proto.free_public_memory());
  out_info->ulTotalPrivateMemory =
      static_cast<CK_ULONG>(proto.total_private_memory());
  out_info->ulFreePrivateMemory =
      static_cast<CK_ULONG>(proto.free_private_memory());

  if (!ProtoToVersion(proto.hardware_version(), &out_info->hardwareVersion) ||
      !ProtoToVersion(proto.firmware_version(), &out_info->firmwareVersion))
    return false;

  return true;
}

TokenInfo TokenInfoToProto(const CK_TOKEN_INFO* info) {
  DCHECK(info);
  TokenInfo proto;
  proto.set_label(CopyToString(info->label, 32));
  proto.set_manufacturer_id(CopyToString(info->manufacturerID, 32));
  proto.set_model(CopyToString(info->model, 16));
  proto.set_serial_number(CopyToString(info->serialNumber, 16));
  proto.set_flags(static_cast<uint64_t>(info->flags));
  proto.set_max_session_count(static_cast<uint64_t>(info->ulMaxSessionCount));
  proto.set_session_count(static_cast<uint64_t>(info->ulSessionCount));
  proto.set_max_session_count_rw(
      static_cast<uint64_t>(info->ulMaxRwSessionCount));
  proto.set_session_count_rw(static_cast<uint64_t>(info->ulRwSessionCount));
  proto.set_max_pin_len(static_cast<uint64_t>(info->ulMaxPinLen));
  proto.set_min_pin_len(static_cast<uint64_t>(info->ulMinPinLen));
  proto.set_total_public_memory(
      static_cast<uint64_t>(info->ulTotalPublicMemory));
  proto.set_free_public_memory(static_cast<uint64_t>(info->ulFreePublicMemory));
  proto.set_total_private_memory(
      static_cast<uint64_t>(info->ulTotalPrivateMemory));
  proto.set_free_private_memory(
      static_cast<uint64_t>(info->ulFreePrivateMemory));
  VersionToProto(&info->hardwareVersion, proto.mutable_hardware_version());
  VersionToProto(&info->firmwareVersion, proto.mutable_firmware_version());
  return proto;
}

}  // namespace chaps
