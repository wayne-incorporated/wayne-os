// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/update_fw.h"
#include "hammerd/vb21_struct.h"

#include <fmap.h>

#include <algorithm>
#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <openssl/rand.h>

namespace hammerd {

constexpr unsigned int kTransferTimeoutMs = 5000;

const char* ToString(UpdateExtraCommand subcommand) {
  switch (subcommand) {
    case UpdateExtraCommand::kImmediateReset:
      return "ImmediateReset";
    case UpdateExtraCommand::kJumpToRW:
      return "JumpToRW";
    case UpdateExtraCommand::kStayInRO:
      return "StayInRO";
    case UpdateExtraCommand::kUnlockRW:
      return "UnlockRW";
    case UpdateExtraCommand::kUnlockRollback:
      return "UnlockRollback";
    case UpdateExtraCommand::kInjectEntropy:
      return "InjectEntropy";
    case UpdateExtraCommand::kPairChallenge:
      return "PairChallenge";
    case UpdateExtraCommand::kTouchpadInfo:
      return "TouchpadInfo";
    case UpdateExtraCommand::kConsoleReadInit:
      return "ConsoleReadInit";
    case UpdateExtraCommand::kConsoleReadNext:
      return "ConsoleReadNext";
    default:
      return "UNKNOWN_COMMAND";
  }
}

const char* ToString(SectionName name) {
  switch (name) {
    case SectionName::RO:
      return "RO";
    case SectionName::RW:
      return "RW";
    default:
      return "UNKNOWN_SECTION";
  }
}

SectionName OtherSection(SectionName name) {
  switch (name) {
    case SectionName::RO:
      return SectionName::RW;
    case SectionName::RW:
      return SectionName::RO;
    default:
      return SectionName::Invalid;
  }
}

SectionInfo::SectionInfo(SectionName name)
    : SectionInfo(name, 0, 0, "", 0, 1) {}

SectionInfo::SectionInfo(SectionName name,
                         uint32_t offset,
                         uint32_t size,
                         const char* version_str,
                         int32_t rollback,
                         int32_t key_version)
    : name(name),
      offset(offset),
      size(size),
      rollback(rollback),
      key_version(key_version) {
  if (strlen(version_str) >= sizeof(version)) {
    LOG(ERROR) << "The version name is larger than the reserved size. "
               << "Discard the extra part.";
  }

  // Note that strncpy will always write a trailing '\0' *unless*
  // strlen(version_str) >= sizeof(version). Hence, we unconditionally
  // guarantee that the last byte of `version` is always '\0'.
  strncpy(version, version_str, sizeof(version));
  version[sizeof(version) - 1] = '\0';
}

bool operator==(const SectionInfo& lhs, const SectionInfo& rhs) {
  return lhs.name == rhs.name && lhs.offset == rhs.offset &&
         lhs.size == rhs.size &&
         strncmp(lhs.version, rhs.version, sizeof(lhs.version)) == 0 &&
         lhs.rollback == rhs.rollback && lhs.key_version == rhs.key_version;
}

bool operator!=(const SectionInfo& lhs, const SectionInfo& rhs) {
  return !(lhs == rhs);
}

FirmwareUpdater::FirmwareUpdater(std::unique_ptr<UsbEndpointInterface> endpoint)
    : FirmwareUpdater(std::move(endpoint), std::make_unique<Fmap>()) {}

FirmwareUpdater::FirmwareUpdater(std::unique_ptr<UsbEndpointInterface> endpoint,
                                 std::unique_ptr<FmapInterface> fmap)
    : endpoint_(std::move(endpoint)),
      fmap_(std::move(fmap)),
      targ_(),
      ec_image_(""),
      sections_() {}

bool FirmwareUpdater::UsbSysfsExists() {
  return endpoint_->UsbSysfsExists();
}

UsbConnectStatus FirmwareUpdater::ConnectUsb() {
  return endpoint_->Connect();
}

UsbConnectStatus FirmwareUpdater::TryConnectUsb() {
  constexpr unsigned int kFlushTimeoutMs = 10;
  constexpr unsigned int kTimeoutMs = 1000;
  constexpr unsigned int kIntervalMs = 100;

  LOG(INFO) << "Trying to connect to USB endpoint.";
  auto start_time = base::Time::Now();
  int64_t duration = 0;
  while (true) {
    UsbConnectStatus ret = endpoint_->Connect();
    // Short-circuit if we have a strange device, since a retry will make
    // no difference.
    if (ret == UsbConnectStatus::kInvalidDevice) {
      return ret;
    }

    if (ret == UsbConnectStatus::kSuccess) {
      // Flush data from the EC's "out" buffer.  There may be leftover data
      // in this buffer from a previous failure.
      const size_t buf_len = endpoint_->GetChunkLength();
      std::unique_ptr<uint8_t[]> buf(new uint8_t[buf_len]);
      while (endpoint_->Receive(buf.get(), buf_len, true, kFlushTimeoutMs) >
             0) {
        LOG(INFO) << "Flushing data...";
      }

      // If we can't properly parse the section version string, the device
      // is considered invalid.
      return FetchVersion() ? ret : UsbConnectStatus::kInvalidDevice;
    }

    duration = (base::Time::Now() - start_time).InMilliseconds();
    if (duration > kTimeoutMs) {
      break;
    }
    base::PlatformThread::Sleep(base::Milliseconds(kIntervalMs));
  }
  LOG(ERROR) << "Failed to connect USB endpoint.";
  return UsbConnectStatus::kUsbPathEmpty;
}

bool FirmwareUpdater::FetchVersion() {
  // Grab and parse the configuration string from USB endpoint.
  version_ = endpoint_->GetConfigurationString();
  if (version_.empty()) {
    LOG(ERROR) << "Empty version from configuration string descriptor.";
    return false;
  }
  // In newer EC builds, the version is prefixed by either "RO:" or "RW:".
  // Remove the first three characters if this is the case.  Require at least
  // one character after removing the prefix.
  if (version_.length() > 3 && version_[2] == ':') {
    version_ = version_.erase(0, 3);
  }
  LOG(INFO) << "Current section version: " << version_;
  return true;
}

void FirmwareUpdater::CloseUsb() {
  endpoint_->Close();
}

bool FmapAreaOutOfBounds(const struct fmap_area* area, size_t len) {
  size_t start = area->offset;
  size_t end = area->offset + area->size;

  if (end < start || end > len) {
    LOG(ERROR) << "FMAP area " << area->name << " beyond ec_image size.";
    return true;
  }

  return false;
}

bool FirmwareUpdater::LoadEcImage(const std::string& ec_image) {
  ec_image_.clear();
  sections_.clear();
  sections_.push_back(SectionInfo(SectionName::RO));
  sections_.push_back(SectionInfo(SectionName::RW));
  uint8_t* image_ptr =
      const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(ec_image.data()));
  size_t len = ec_image.size();

  int64_t offset = fmap_->Find(image_ptr, len);
  if (offset < 0) {
    LOG(ERROR) << "Cannot find FMAP in ec_image.";
    return false;
  }

  fmap* fmap = reinterpret_cast<struct fmap*>(image_ptr + offset);
  size_t fmap_end = offset + sizeof(*fmap);
  if (fmap_end < offset || fmap_end > len) {
    LOG(ERROR) << "FMAP beyond ec_image size.";
    return false;
  }
  if (fmap->size != len) {
    LOG(ERROR) << "Mismatch between FMAP size and ec_image size.";
    return false;
  }
  size_t area_size = sizeof(fmap_area) * fmap->nareas;
  if (fmap_end + area_size < fmap_end || fmap_end + area_size > len) {
    LOG(ERROR) << "FMAP areas beyond ec_image size.";
    return false;
  }

  for (auto& section : sections_) {
    const char* fmap_name;
    const char* fmap_fwid_name;
    const char* fmap_rollback_name = nullptr;
    const char* fmap_key_name = nullptr;

    if (section.name == SectionName::RO) {
      fmap_name = "EC_RO";
      fmap_fwid_name = "RO_FRID";
    } else if (section.name == SectionName::RW) {
      fmap_name = "EC_RW";
      fmap_fwid_name = "RW_FWID";
      fmap_rollback_name = "RW_RBVER";
      // Key version comes from key RO (RW signature does not
      // contain the key version.
      fmap_key_name = "KEY_RO";
    } else {
      LOG(ERROR) << "Invalid section name";
      return false;
    }

    const fmap_area* fmaparea = fmap_->FindArea(fmap, fmap_name);
    if (!fmaparea) {
      LOG(ERROR) << "Cannot find FMAP area: " << fmap_name;
      return false;
    }
    if (FmapAreaOutOfBounds(fmaparea, len))
      return false;
    section.offset = fmaparea->offset;
    section.size = fmaparea->size;

    fmaparea = fmap_->FindArea(fmap, fmap_fwid_name);
    if (!fmaparea) {
      LOG(ERROR) << "Cannot find FMAP area: " << fmap_fwid_name;
      return false;
    }
    if (FmapAreaOutOfBounds(fmaparea, len))
      return false;
    if (fmaparea->size != sizeof(section.version)) {
      LOG(ERROR) << "Invalid fwid size\n";
      return false;
    }
    memcpy(section.version, image_ptr + fmaparea->offset, fmaparea->size);

    if (fmap_rollback_name &&
        (fmaparea = fmap_->FindArea(fmap, fmap_rollback_name))) {
      if (FmapAreaOutOfBounds(fmaparea, len))
        return false;
      if (fmaparea->size != sizeof(section.rollback)) {
        LOG(ERROR) << "Invalid section rollback size\n";
        return false;
      }
      section.rollback =
          *(reinterpret_cast<const int32_t*>(image_ptr + fmaparea->offset));
    } else {
      section.rollback = -1;
    }

    if (fmap_key_name && (fmaparea = fmap_->FindArea(fmap, fmap_key_name))) {
      if (FmapAreaOutOfBounds(fmaparea, len))
        return false;
      auto key = reinterpret_cast<const vb21_packed_key*>(image_ptr +
                                                          fmaparea->offset);
      if (fmaparea->size < sizeof(struct vb21_packed_key)) {
        LOG(ERROR) << "Invalid vb21_packed_key size\n";
        return false;
      }
      section.key_version = key->key_version;
    } else {
      section.key_version = -1;
    }
  }

  ec_image_ = ec_image;
  LOG(INFO) << "### On-disk Firmware Update ###";
  for (const auto& section : sections_) {
    LOG(INFO) << base::StringPrintf(
        "  %s: offset=0x%08x/0x%08x version=%s rollback=%d key_version=%d",
        ToString(section.name), section.offset, section.size, section.version,
        section.rollback, section.key_version);
  }
  return true;
}

bool FirmwareUpdater::LoadTouchpadImage(const std::string& touchpad_image) {
  touchpad_image_ = touchpad_image;
  return true;
}

SectionName FirmwareUpdater::CurrentSection() const {
  for (const auto& section : sections_) {
    if (targ_.offset == section.offset) {
      return OtherSection(section.name);
    }
  }
  return SectionName::Invalid;
}

bool FirmwareUpdater::ValidKey() const {
  SectionInfo local_section = sections_[static_cast<int>(SectionName::RW)];
  LOG(INFO) << "ValidKey: key_version [EC] " << targ_.key_version << " vs. "
            << local_section.key_version << " [update]";
  return targ_.key_version == local_section.key_version;
}

int FirmwareUpdater::CompareRollback() const {
  SectionInfo local_section = sections_[static_cast<int>(SectionName::RW)];
  LOG(INFO) << "CompareRollback: rollback [EC] " << targ_.min_rollback
            << " vs. " << local_section.rollback << " [update]";
  if (local_section.rollback > targ_.min_rollback)
    return 1;
  if (local_section.rollback < targ_.min_rollback)
    return -1;
  return 0;
}

bool FirmwareUpdater::VersionMismatch(SectionName section_name) const {
  // section_name refers to the section about which we are inquiring.
  // local_section refers to the particular section of the local firmware file.
  // CurrentSection() refers to the currently-running section.
  //
  // targ_ header only provides information about the non-running section,
  // so the way we detect the version string depends on CurrentSection().
  SectionInfo local_section = sections_[static_cast<int>(section_name)];

  const char* rw_version =
      CurrentSection() == SectionName::RW ? version_.c_str() : targ_.version;
  const char* ro_version =
      CurrentSection() == SectionName::RO ? version_.c_str() : targ_.version;
  const char* version =
      section_name == SectionName::RW ? rw_version : ro_version;

  LOG(INFO) << "VersionMismatch: version [EC] " << version << " vs. "
            << local_section.version << " [update]";
  return strncmp(version, local_section.version,
                 sizeof(local_section.version)) != 0;
}

bool FirmwareUpdater::IsSectionLocked(SectionName section_name) const {
  uint32_t mask;
  if (section_name == SectionName::RO) {
    mask = static_cast<uint32_t>(EcFlashProtect::kRONow);
  } else if (section_name == SectionName::RW) {
    mask = static_cast<uint32_t>(EcFlashProtect::kRWNow);
  } else {
    LOG(ERROR) << "Unsupported section for IsSectionLocked: "
               << ToString(section_name);
    return false;
  }
  return (targ_.flash_protection & mask) != 0;
}

// In this definition of "critical", either of the following must be true:
//   - Rollback number has increased; or
//   - Branch tag of RW section is different (defined as "v1.1" in
//     version string "basename_v1.1.1234-1234abcde").
bool FirmwareUpdater::IsCritical() const {
  const std::string new_version{
      sections_[static_cast<int>(SectionName::RW)].version};
  const std::string current_version = GetSectionVersion(SectionName::RW);
  const std::string branch_tag = new_version.substr(0, new_version.rfind("."));
  const bool same_branch_tag = base::StartsWith(current_version, branch_tag,
                                                base::CompareCase::SENSITIVE);
  return !same_branch_tag || CompareRollback() > 0;
}

bool FirmwareUpdater::UnlockRW() {
  return SendSubcommand(UpdateExtraCommand::kUnlockRW);
}

bool FirmwareUpdater::IsRollbackLocked() const {
  uint32_t mask = static_cast<uint32_t>(EcFlashProtect::kRollbackNow);
  return (targ_.flash_protection & mask) != 0;
}

bool FirmwareUpdater::UnlockRollback() {
  return SendSubcommand(UpdateExtraCommand::kUnlockRollback);
}

// Note: It is assumed that when TransferImage is called, hammer EC is in the
// IDLE state.  This function takes care of the entire update process, including
// bringing hammer EC back to the IDLE state afterwards.
bool FirmwareUpdater::TransferImage(SectionName section_name) {
  const uint8_t* image_ptr = reinterpret_cast<const uint8_t*>(ec_image_.data());
  auto section = sections_[static_cast<int>(section_name)];
  LOG(INFO) << "Section to be updated: " << ToString(section.name);
  if (section.offset + section.size > ec_image_.size()) {
    LOG(ERROR) << "EC image length (" << ec_image_.size()
               << ") is smaller than transfer requirements: " << section.offset
               << " + " << section.size;
    return false;
  }
  return TransferSection(image_ptr + section.offset, section.offset,
                         section.size, true);
}

bool FirmwareUpdater::TransferTouchpadFirmware(uint32_t section_addr,
                                               size_t data_len) {
  return TransferSection(
      reinterpret_cast<const uint8_t*>(touchpad_image_.data()), section_addr,
      data_len, false);
}

bool FirmwareUpdater::InjectEntropy() {
  uint8_t entropy[kEntropySize];
  RAND_bytes(entropy, kEntropySize);
  std::string entropy_data(reinterpret_cast<const char*>(entropy),
                           kEntropySize);
  return InjectEntropyWithPayload(entropy_data);
}

bool FirmwareUpdater::InjectEntropyWithPayload(const std::string& payload) {
  if (payload.size() != kEntropySize) {
    LOG(ERROR) << "Entropy size should be " << kEntropySize << " bytes.";
    return false;
  }
  return SendSubcommandWithPayload(UpdateExtraCommand::kInjectEntropy, payload);
}

bool FirmwareUpdater::SendSubcommand(UpdateExtraCommand subcommand) {
  std::string cmd_body = "";
  return SendSubcommandWithPayload(subcommand, cmd_body);
}

bool FirmwareUpdater::SendSubcommandWithPayload(UpdateExtraCommand subcommand,
                                                const std::string& cmd_body) {
  uint8_t response;
  return SendSubcommandReceiveResponse(subcommand, cmd_body, &response,
                                       sizeof(response));
}

bool FirmwareUpdater::SendSubcommandReceiveResponse(
    UpdateExtraCommand subcommand,
    const std::string& cmd_body,
    void* resp,
    size_t resp_size,
    bool allow_less) {
  LOG(INFO) << ">>> SendSubcommand: " << ToString(subcommand);

  uint16_t subcommand_value = static_cast<uint16_t>(subcommand);
  size_t usb_msg_size =
      sizeof(UpdateFrameHeader) + sizeof(subcommand_value) + cmd_body.size();
  std::unique_ptr<UpdateFrameHeader, base::FreeDeleter> ufh(
      static_cast<UpdateFrameHeader*>(malloc(usb_msg_size)));
  if (ufh == nullptr) {
    LOG(ERROR) << "Failed to allocate " << usb_msg_size << " bytes";
    return false;
  }
  ufh->block_size = htobe32(usb_msg_size);
  ufh->block_base = htobe32(kUpdateExtraCmd);
  ufh->block_digest = 0;
  uint16_t* frame_ptr = reinterpret_cast<uint16_t*>(ufh.get() + 1);
  *frame_ptr = htobe16(subcommand_value);
  if (cmd_body.size()) {
    memcpy(frame_ptr + 1, cmd_body.data(), cmd_body.size());
  }

  if (subcommand == UpdateExtraCommand::kImmediateReset) {
    // When sending reset command, we won't get the response. Therefore just
    // check the Send action is successful.
    int sent = endpoint_->Send(ufh.get(), usb_msg_size, false, 0);
    return (sent == usb_msg_size);
  }
  int received =
      endpoint_->Transfer(ufh.get(), usb_msg_size, resp, resp_size, allow_less);
  // The first byte of the response is the status of the subcommand.
  LOG(INFO) << base::StringPrintf("Status of subcommand: %d",
                                  *(reinterpret_cast<uint8_t*>(resp)));
  return (received == resp_size);
}

bool FirmwareUpdater::SendFirstPdu() {
  UpdateFrameHeader ufh;
  FirstResponsePdu rpdu;
  uint32_t return_value;

  constexpr unsigned int kMaximumRunCount = 100;
  constexpr unsigned int kWaitTimeMs = 10;  // Time to wait in between attempts.
  // Retry with ~1000ms timeout to wait for EC to calculate RW signature.
  for (int run_count = 0; run_count < kMaximumRunCount; ++run_count) {
    LOG(INFO) << ">>> SendFirstPdu (attempt " << run_count << ")";
    memset(&ufh, 0, sizeof(ufh));
    ufh.block_size = htobe32(sizeof(ufh));
    if (endpoint_->Send(&ufh, sizeof(ufh)) != sizeof(ufh)) {
      LOG(ERROR) << "Send first update frame header failed.";
      return false;
    }

    // We got something. Check for errors in response.
    size_t rxed_size = endpoint_->Receive(&rpdu, sizeof(rpdu), true);
    const size_t kMinimumResponseSize = 8;
    if (rxed_size < kMinimumResponseSize) {
      LOG(ERROR) << "Unexpected response size: " << rxed_size
                 << ". Response content: "
                 << base::HexEncode(reinterpret_cast<uint8_t*>(&rpdu),
                                    rxed_size);
      return false;
    }

    // Convert endian of the response.
    return_value = be32toh(rpdu.return_value);
    targ_.header_type = be16toh(rpdu.header_type);
    targ_.protocol_version = be16toh(rpdu.protocol_version);
    targ_.maximum_pdu_size = be32toh(rpdu.maximum_pdu_size);
    targ_.flash_protection = be32toh(rpdu.flash_protection);
    targ_.offset = be32toh(rpdu.offset);
    memcpy(targ_.version, rpdu.version, sizeof(rpdu.version));
    targ_.min_rollback = be32toh(rpdu.min_rollback);
    targ_.key_version = be32toh(rpdu.key_version);

    LOG(INFO) << "target running protocol version " << targ_.protocol_version
              << " (type " << targ_.header_type << ")";
    if (targ_.protocol_version != 6) {
      LOG(ERROR) << "Unsupported protocol version " << targ_.protocol_version;
      return false;
    }
    if (targ_.header_type !=
        static_cast<int>(FirstResponsePduHeaderType::kCommon)) {
      LOG(ERROR) << "Unsupported header type " << targ_.header_type;
      return false;
    }
    if (return_value !=
        static_cast<int>(UpdateCommandResponseStatus::kRwsigBusy))
      break;
    LOG(WARNING) << "EC still calculating RW signature, retrying...";
    base::PlatformThread::Sleep(base::Milliseconds(kWaitTimeMs));
  }
  if (return_value) {
    LOG(ERROR) << "Target reporting error " << return_value;
    return false;
  }

  std::string writable_section = ToString(OtherSection(CurrentSection()));
  LOG(INFO) << "### Writable Section: " << writable_section << " ###";
  LOG(INFO) << base::StringPrintf(
      "  Maximum PDU size: %d, Flash protection: %04x, Version: %s, "
      "Key version: %d, Minimum rollback: %d, Writeable at offset: 0x%x",
      targ_.maximum_pdu_size, targ_.flash_protection, targ_.version,
      targ_.key_version, targ_.min_rollback, targ_.offset);
  return true;
}

void FirmwareUpdater::SendDone() {
  // Send stop request, ignoring reply.
  LOG(INFO) << ">>> SendDone";
  uint32_t out = htobe32(kUpdateDoneCmd);
  uint8_t unused_received;
  endpoint_->Transfer(&out, sizeof(out), &unused_received, 1, false);
}

bool FirmwareUpdater::TransferSection(const uint8_t* data_ptr,
                                      uint32_t section_addr,
                                      size_t data_len,
                                      bool use_block_skip) {
  if (!SendFirstPdu()) {
    LOG(ERROR) << "Failed to send the first PDU.";
    return false;
  }

  bool ret = true;
  LOG(INFO) << "Sending 0x" << std::hex << data_len << " bytes to 0x"
            << section_addr << std::dec;
  while (data_len > 0) {
    // prepare the header to prepend to the block.
    size_t payload_size = std::min<size_t>(data_len, targ_.maximum_pdu_size);
    UpdateFrameHeader ufh;
    ufh.block_size = htobe32(payload_size + sizeof(UpdateFrameHeader));
    ufh.block_base = htobe32(section_addr);
    ufh.block_digest = 0;
    LOG(INFO) << "Update frame header: " << std::hex << "0x" << ufh.block_size
              << " "
              << "0x" << ufh.block_base << " "
              << "0x" << ufh.block_digest << std::dec;
    if (!TransferBlock(&ufh, data_ptr, payload_size, use_block_skip)) {
      LOG(ERROR) << "Failed to transfer block, " << data_len << " to go";
      ret = false;
      break;
    }
    data_len -= payload_size;
    data_ptr += payload_size;
    section_addr += payload_size;
  }
  SendDone();

  return ret;
}

bool FirmwareUpdater::CheckEmptyBlock(const uint8_t* transfer_data_ptr,
                                      size_t payload_size) {
  for (int i = 0; i < payload_size; i++) {
    if (transfer_data_ptr[i] != 0xff)
      return false;
  }
  return true;
}

bool FirmwareUpdater::TransferBlock(UpdateFrameHeader* ufh,
                                    const uint8_t* transfer_data_ptr,
                                    size_t payload_size,
                                    bool use_block_skip) {
  // The section space must be erased before the update is attempted.
  // Thus we can skip blocks entirely composed of 0xff. However, this doesn't
  // apply for touchpad update.
  if (use_block_skip && CheckEmptyBlock(transfer_data_ptr, payload_size)) {
    LOG(INFO) << "Block is all 0xff; skipping.";
    return true;
  }

  // First send the header.
  LOG(INFO) << "Send the block header: "
            << base::HexEncode(reinterpret_cast<uint8_t*>(ufh), sizeof(*ufh));
  endpoint_->Send(ufh, sizeof(*ufh));

  // Now send the block, chunk by chunk.
  size_t transfer_size = 0;
  while (transfer_size < payload_size) {
    int chunk_size = std::min<size_t>(endpoint_->GetChunkLength(),
                                      payload_size - transfer_size);
    endpoint_->Send(transfer_data_ptr, chunk_size);
    transfer_data_ptr += chunk_size;
    transfer_size += chunk_size;
  }

  // Now get the reply.
  uint32_t reply;
  if (endpoint_->Receive(&reply, sizeof(reply), true, kTransferTimeoutMs) ==
      -1) {
    return false;
  }
  reply = *(reinterpret_cast<uint8_t*>(&reply));
  if (reply) {
    LOG(ERROR) << "Error: status " << static_cast<int>(reply);
    return false;
  }
  return true;
}

std::string FirmwareUpdater::GetEcImageVersion() const {
  return sections_[0].version;
}

std::string FirmwareUpdater::ReadConsole() {
  std::string ret;
  constexpr size_t CHUNK_SIZE = 64;
  size_t response_size = 1;
  char response[CHUNK_SIZE] = {'\0'};
  const std::string next_payload = "\1";
  bool cmd_ret;

  cmd_ret = SendSubcommandReceiveResponse(UpdateExtraCommand::kConsoleReadInit,
                                          "", reinterpret_cast<void*>(response),
                                          response_size);
  if (!cmd_ret) {
    LOG(ERROR) << "Failed to init before reading console.";
    return ret;
  }

  while (true) {
    response_size = CHUNK_SIZE;
    // Enable allow_less because response size can vary.
    cmd_ret = SendSubcommandReceiveResponse(
        UpdateExtraCommand::kConsoleReadNext, next_payload,
        reinterpret_cast<void*>(response), response_size, true);
    if (response[0] == 0)
      break;

    response[response_size - 1] = '\0';
    ret.append(response);
  }

  return ret;
}

const FirstResponsePdu* FirmwareUpdater::GetFirstResponsePdu() const {
  return &targ_;
}

std::string FirmwareUpdater::GetSectionVersion(SectionName section_name) const {
  if (section_name == SectionName::Invalid ||
      CurrentSection() == SectionName::Invalid) {
    return "Unknown";
  }
  if (section_name == CurrentSection()) {
    return version_;
  }
  return std::string(targ_.version);
}

}  // namespace hammerd
