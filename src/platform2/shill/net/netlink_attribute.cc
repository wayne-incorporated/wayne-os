// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/netlink_attribute.h"

#include <linux/genetlink.h>

#include <cctype>

#include <base/check.h>
#include <base/format_macros.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "shill/net/attribute_list.h"
#include "shill/net/control_netlink_attribute.h"
#include "shill/net/nl80211_attribute.h"

namespace shill {

NetlinkAttribute::NetlinkAttribute(int id,
                                   const char* id_string,
                                   Type datatype,
                                   const char* datatype_string)
    : has_a_value_(false),
      id_(id),
      id_string_(id_string),
      datatype_(datatype),
      datatype_string_(datatype_string) {}

// static
std::unique_ptr<NetlinkAttribute> NetlinkAttribute::NewNl80211AttributeFromId(
    NetlinkMessage::MessageContext context, int id) {
  switch (id) {
    case NL80211_ATTR_BSS:
      return std::make_unique<Nl80211AttributeBss>();
    case NL80211_ATTR_CENTER_FREQ1:
      return std::make_unique<Nl80211AttributeCenterFreq1>();
    case NL80211_ATTR_CENTER_FREQ2:
      return std::make_unique<Nl80211AttributeCenterFreq2>();
    case NL80211_ATTR_CHANNEL_WIDTH:
      return std::make_unique<Nl80211AttributeChannelWidth>();
    case NL80211_ATTR_CIPHER_SUITES:
      return std::make_unique<Nl80211AttributeCipherSuites>();
    case NL80211_ATTR_CONTROL_PORT_ETHERTYPE:
      return std::make_unique<Nl80211AttributeControlPortEthertype>();
    case NL80211_ATTR_COOKIE:
      return std::make_unique<Nl80211AttributeCookie>();
    case NL80211_ATTR_CQM:
      return std::make_unique<Nl80211AttributeCqm>();
    case NL80211_ATTR_DEVICE_AP_SME:
      return std::make_unique<Nl80211AttributeDeviceApSme>();
    case NL80211_ATTR_DFS_REGION:
      return std::make_unique<Nl80211AttributeDfsRegion>();
    case NL80211_ATTR_DISCONNECTED_BY_AP:
      return std::make_unique<Nl80211AttributeDisconnectedByAp>();
    case NL80211_ATTR_DURATION:
      return std::make_unique<Nl80211AttributeDuration>();
    case NL80211_ATTR_FEATURE_FLAGS:
      return std::make_unique<Nl80211AttributeFeatureFlags>();
    case NL80211_ATTR_FRAME:
      return std::make_unique<Nl80211AttributeFrame>();
    case NL80211_ATTR_GENERATION:
      return std::make_unique<Nl80211AttributeGeneration>();
    case NL80211_ATTR_HT_CAPABILITY_MASK:
      return std::make_unique<Nl80211AttributeHtCapabilityMask>();
    case NL80211_ATTR_IFINDEX:
      return std::make_unique<Nl80211AttributeIfindex>();
    case NL80211_ATTR_IFTYPE:
      return std::make_unique<Nl80211AttributeIftype>();
    case NL80211_ATTR_INTERFACE_COMBINATIONS:
      return std::make_unique<Nl80211AttributeInterfaceCombinations>();
    case NL80211_ATTR_KEY_IDX:
      return std::make_unique<Nl80211AttributeKeyIdx>();
    case NL80211_ATTR_KEY_SEQ:
      return std::make_unique<Nl80211AttributeKeySeq>();
    case NL80211_ATTR_KEY_TYPE:
      return std::make_unique<Nl80211AttributeKeyType>();
    case NL80211_ATTR_MAC:
      return std::make_unique<Nl80211AttributeMac>();
    case NL80211_ATTR_MAX_MATCH_SETS:
      return std::make_unique<Nl80211AttributeMaxMatchSets>();
    case NL80211_ATTR_MAX_NUM_PMKIDS:
      return std::make_unique<Nl80211AttributeMaxNumPmkids>();
    case NL80211_ATTR_MAX_NUM_SCAN_SSIDS:
      return std::make_unique<Nl80211AttributeMaxNumScanSsids>();
    case NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS:
      return std::make_unique<Nl80211AttributeMaxNumSchedScanSsids>();
    case NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION:
      return std::make_unique<Nl80211AttributeMaxRemainOnChannelDuration>();
    case NL80211_ATTR_MAX_SCAN_IE_LEN:
      return std::make_unique<Nl80211AttributeMaxScanIeLen>();
    case NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN:
      return std::make_unique<Nl80211AttributeMaxSchedScanIeLen>();
    case NL80211_ATTR_MPATH_INFO:
      return std::make_unique<Nl80211AttributeMPathInfo>();
    case NL80211_ATTR_OFFCHANNEL_TX_OK:
      return std::make_unique<Nl80211AttributeOffchannelTxOk>();
    case NL80211_ATTR_PROBE_RESP_OFFLOAD:
      return std::make_unique<Nl80211AttributeProbeRespOffload>();
    case NL80211_ATTR_REASON_CODE:
      return std::make_unique<Nl80211AttributeReasonCode>();
    case NL80211_ATTR_REG_ALPHA2:
      return std::make_unique<Nl80211AttributeRegAlpha2>();
    case NL80211_ATTR_REG_INITIATOR:
      return std::make_unique<Nl80211AttributeRegInitiator>();
    case NL80211_ATTR_REG_RULES:
      return std::make_unique<Nl80211AttributeRegRules>();
    case NL80211_ATTR_REG_TYPE:
      return std::make_unique<Nl80211AttributeRegType>();
    case NL80211_ATTR_RESP_IE:
      return std::make_unique<Nl80211AttributeRespIe>();
    case NL80211_ATTR_ROAM_SUPPORT:
      return std::make_unique<Nl80211AttributeRoamSupport>();
    case NL80211_ATTR_SCAN_FREQUENCIES:
      return std::make_unique<Nl80211AttributeScanFrequencies>();
    case NL80211_ATTR_SCAN_SSIDS:
      return std::make_unique<Nl80211AttributeScanSsids>();
    case NL80211_ATTR_STA_INFO:
      return std::make_unique<Nl80211AttributeStaInfo>();
    case NL80211_ATTR_STATUS_CODE:
      return std::make_unique<Nl80211AttributeStatusCode>();
    case NL80211_ATTR_SUPPORT_AP_UAPSD:
      return std::make_unique<Nl80211AttributeSupportApUapsd>();
    case NL80211_ATTR_SUPPORT_IBSS_RSN:
      return std::make_unique<Nl80211AttributeSupportIbssRsn>();
    case NL80211_ATTR_SUPPORT_MESH_AUTH:
      return std::make_unique<Nl80211AttributeSupportMeshAuth>();
    case NL80211_ATTR_SUPPORTED_COMMANDS:
      return std::make_unique<Nl80211AttributeSupportedCommands>();
    case NL80211_ATTR_SUPPORTED_IFTYPES:
      return std::make_unique<Nl80211AttributeSupportedIftypes>();
    case NL80211_ATTR_SURVEY_INFO:
      return std::make_unique<Nl80211AttributeSurveyInfo>();
    case NL80211_ATTR_TDLS_EXTERNAL_SETUP:
      return std::make_unique<Nl80211AttributeTdlsExternalSetup>();
    case NL80211_ATTR_TDLS_SUPPORT:
      return std::make_unique<Nl80211AttributeTdlsSupport>();
    case NL80211_ATTR_TIMED_OUT:
      return std::make_unique<Nl80211AttributeTimedOut>();
    case NL80211_ATTR_WIPHY:
      return std::make_unique<Nl80211AttributeWiphy>();
    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX:
      return std::make_unique<Nl80211AttributeWiphyAntennaAvailRx>();
    case NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX:
      return std::make_unique<Nl80211AttributeWiphyAntennaAvailTx>();
    case NL80211_ATTR_WIPHY_ANTENNA_RX:
      return std::make_unique<Nl80211AttributeWiphyAntennaRx>();
    case NL80211_ATTR_WIPHY_ANTENNA_TX:
      return std::make_unique<Nl80211AttributeWiphyAntennaTx>();
    case NL80211_ATTR_WIPHY_BANDS:
      return std::make_unique<Nl80211AttributeWiphyBands>();
    case NL80211_ATTR_WIPHY_CHANNEL_TYPE:
      return std::make_unique<Nl80211AttributeChannelType>();
    case NL80211_ATTR_WIPHY_COVERAGE_CLASS:
      return std::make_unique<Nl80211AttributeWiphyCoverageClass>();
    case NL80211_ATTR_WIPHY_FRAG_THRESHOLD:
      return std::make_unique<Nl80211AttributeWiphyFragThreshold>();
    case NL80211_ATTR_WIPHY_FREQ:
      return std::make_unique<Nl80211AttributeWiphyFreq>();
    case NL80211_ATTR_WIPHY_NAME:
      return std::make_unique<Nl80211AttributeWiphyName>();
    case NL80211_ATTR_WIPHY_RETRY_LONG:
      return std::make_unique<Nl80211AttributeWiphyRetryLong>();
    case NL80211_ATTR_WIPHY_RETRY_SHORT:
      return std::make_unique<Nl80211AttributeWiphyRetryShort>();
    case NL80211_ATTR_WIPHY_RTS_THRESHOLD:
      return std::make_unique<Nl80211AttributeWiphyRtsThreshold>();
    case NL80211_ATTR_WIPHY_SELF_MANAGED_REG:
      return std::make_unique<Nl80211AttributeWiphySelfManagedReg>();
    case NL80211_ATTR_WOWLAN_TRIGGERS:
      return std::make_unique<Nl80211AttributeWowlanTriggers>(context);
    case NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED:
      return std::make_unique<Nl80211AttributeWowlanTriggersSupported>();
    default:
      return std::make_unique<NetlinkAttributeGeneric>(id);
  }
}

// static
std::unique_ptr<NetlinkAttribute> NetlinkAttribute::NewControlAttributeFromId(
    int id) {
  switch (id) {
    case CTRL_ATTR_FAMILY_ID:
      return std::make_unique<ControlAttributeFamilyId>();
    case CTRL_ATTR_FAMILY_NAME:
      return std::make_unique<ControlAttributeFamilyName>();
    case CTRL_ATTR_VERSION:
      return std::make_unique<ControlAttributeVersion>();
    case CTRL_ATTR_HDRSIZE:
      return std::make_unique<ControlAttributeHdrSize>();
    case CTRL_ATTR_MAXATTR:
      return std::make_unique<ControlAttributeMaxAttr>();
    case CTRL_ATTR_OPS:
      return std::make_unique<ControlAttributeAttrOps>();
    case CTRL_ATTR_MCAST_GROUPS:
      return std::make_unique<ControlAttributeMcastGroups>();
    default:
      return std::make_unique<NetlinkAttributeGeneric>(id);
  }
}

// Duplicate attribute data, store in map indexed on |id|.
bool NetlinkAttribute::InitFromValue(const ByteString& input) {
  data_ = input;
  return true;
}

bool NetlinkAttribute::GetU8Value(uint8_t* value) const {
  LOG(ERROR) << "Attribute is not of type 'U8'";
  return false;
}

bool NetlinkAttribute::SetU8Value(uint8_t value) {
  LOG(ERROR) << "Attribute is not of type 'U8'";
  return false;
}

bool NetlinkAttribute::GetU16Value(uint16_t* value) const {
  LOG(ERROR) << "Attribute is not of type 'U16'";
  return false;
}

bool NetlinkAttribute::SetU16Value(uint16_t value) {
  LOG(ERROR) << "Attribute is not of type 'U16'";
  return false;
}

bool NetlinkAttribute::GetU32Value(uint32_t* value) const {
  LOG(ERROR) << "Attribute is not of type 'U32'";
  return false;
}

bool NetlinkAttribute::SetU32Value(uint32_t value) {
  LOG(ERROR) << "Attribute is not of type 'U32'";
  return false;
}

bool NetlinkAttribute::GetU64Value(uint64_t* value) const {
  LOG(ERROR) << "Attribute is not of type 'U64'";
  return false;
}

bool NetlinkAttribute::SetU64Value(uint64_t value) {
  LOG(ERROR) << "Attribute is not of type 'U64'";
  return false;
}

bool NetlinkAttribute::GetFlagValue(bool* value) const {
  LOG(ERROR) << "Attribute is not of type 'Flag'";
  return false;
}

bool NetlinkAttribute::SetFlagValue(bool value) {
  LOG(ERROR) << "Attribute is not of type 'Flag'";
  return false;
}

bool NetlinkAttribute::GetStringValue(std::string* value) const {
  LOG(ERROR) << "Attribute is not of type 'String'";
  return false;
}

bool NetlinkAttribute::SetStringValue(const std::string& value) {
  LOG(ERROR) << "Attribute is not of type 'String'";
  return false;
}

bool NetlinkAttribute::GetNestedAttributeList(AttributeListRefPtr* value) {
  LOG(ERROR) << "Attribute is not of type 'Nested'";
  return false;
}

bool NetlinkAttribute::ConstGetNestedAttributeList(
    AttributeListConstRefPtr* value) const {
  LOG(ERROR) << "Attribute is not of type 'Nested'";
  return false;
}

bool NetlinkAttribute::SetNestedHasAValue() {
  LOG(ERROR) << "Attribute is not of type 'Nested'";
  return false;
}

bool NetlinkAttribute::GetRawValue(ByteString* value) const {
  LOG(ERROR) << "Attribute is not of type 'Raw'";
  return false;
}

bool NetlinkAttribute::SetRawValue(const ByteString new_value) {
  LOG(ERROR) << "Attribute is not of type 'Raw'";
  return false;
}

void NetlinkAttribute::Print(int log_level, int indent) const {
  std::string attribute_value;
  VLOG(log_level) << HeaderToPrint(indent) << " "
                  << (ToString(&attribute_value) ? attribute_value
                                                 : "<DOES NOT EXIST>");
}

std::string NetlinkAttribute::RawToString() const {
  std::string output = " === RAW: ";

  if (!has_a_value_) {
    base::StringAppendF(&output, "(empty)");
    return output;
  }

  uint16_t length = data_.GetLength();
  const uint8_t* const_data = data_.GetConstData();

  base::StringAppendF(&output, "len=%u", length);
  output.append(" DATA: ");
  for (int i = 0; i < length; ++i) {
    base::StringAppendF(&output, "[%d]=%02x ", i, *(const_data) + i);
  }
  output.append(" ==== ");
  return output;
}

std::string NetlinkAttribute::HeaderToPrint(int indent) const {
  static const int kSpacesPerIndent = 2;
  return base::StringPrintf("%*s%s(%d) %s %s=", indent * kSpacesPerIndent, "",
                            id_string(), id(), datatype_string(),
                            ((has_a_value()) ? "" : "UNINITIALIZED "));
}

ByteString NetlinkAttribute::EncodeGeneric(const unsigned char* data,
                                           size_t num_bytes) const {
  ByteString result;
  if (has_a_value_) {
    nlattr header;
    header.nla_type = id();
    header.nla_len = NLA_HDRLEN + num_bytes;
    result =
        ByteString(reinterpret_cast<unsigned char*>(&header), sizeof(header));
    result.Resize(NLA_HDRLEN);  // Add padding after the header.
    if (data && (num_bytes != 0)) {
      result.Append(ByteString(data, num_bytes));
    }
    result.Resize(NLA_ALIGN(result.GetLength()));  // Add padding.
  }
  return result;
}

// NetlinkU8Attribute

const char NetlinkU8Attribute::kMyTypeString[] = "uint8_t";
const NetlinkAttribute::Type NetlinkU8Attribute::kType =
    NetlinkAttribute::kTypeU8;

bool NetlinkU8Attribute::InitFromValue(const ByteString& input) {
  uint8_t data;
  if (!input.CopyData(sizeof(data), &data)) {
    LOG(ERROR) << "Invalid |input| for " << id_string() << " of type "
               << datatype_string() << ": expected " << sizeof(data)
               << " bytes but only had " << input.GetLength() << ".";
    return false;
  }
  SetU8Value(data);
  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkU8Attribute::GetU8Value(uint8_t* output) const {
  if (!has_a_value_) {
    VLOG(7) << "U8 attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkU8Attribute::SetU8Value(uint8_t new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkU8Attribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  uint8_t value;
  if (!GetU8Value(&value))
    return false;
  *output = base::StringPrintf("%u", value);
  return true;
}

ByteString NetlinkU8Attribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(
      reinterpret_cast<const unsigned char*>(&value_), sizeof(value_));
}

// NetlinkU16Attribute

const char NetlinkU16Attribute::kMyTypeString[] = "uint16_t";
const NetlinkAttribute::Type NetlinkU16Attribute::kType =
    NetlinkAttribute::kTypeU16;

bool NetlinkU16Attribute::InitFromValue(const ByteString& input) {
  uint16_t data;
  if (!input.CopyData(sizeof(data), &data)) {
    LOG(ERROR) << "Invalid |input| for " << id_string() << " of type "
               << datatype_string() << ": expected " << sizeof(data)
               << " bytes but only had " << input.GetLength() << ".";
    return false;
  }

  SetU16Value(data);
  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkU16Attribute::GetU16Value(uint16_t* output) const {
  if (!has_a_value_) {
    VLOG(7) << "U16 attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkU16Attribute::SetU16Value(uint16_t new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkU16Attribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  uint16_t value;
  if (!GetU16Value(&value))
    return false;
  *output = base::StringPrintf("%u", value);
  return true;
}

ByteString NetlinkU16Attribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(
      reinterpret_cast<const unsigned char*>(&value_), sizeof(value_));
}

// NetlinkU32Attribute::

const char NetlinkU32Attribute::kMyTypeString[] = "uint32_t";
const NetlinkAttribute::Type NetlinkU32Attribute::kType =
    NetlinkAttribute::kTypeU32;

bool NetlinkU32Attribute::InitFromValue(const ByteString& input) {
  uint32_t data;
  if (!input.CopyData(sizeof(data), &data)) {
    LOG(ERROR) << "Invalid |input| for " << id_string() << " of type "
               << datatype_string() << ": expected " << sizeof(data)
               << " bytes but only had " << input.GetLength() << ".";
    return false;
  }

  SetU32Value(data);
  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkU32Attribute::GetU32Value(uint32_t* output) const {
  if (!has_a_value_) {
    VLOG(7) << "U32 attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkU32Attribute::SetU32Value(uint32_t new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkU32Attribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  uint32_t value;
  if (!GetU32Value(&value))
    return false;
  *output = base::StringPrintf("%" PRIu32, value);
  return true;
}

ByteString NetlinkU32Attribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(
      reinterpret_cast<const unsigned char*>(&value_), sizeof(value_));
}

// NetlinkU64Attribute

const char NetlinkU64Attribute::kMyTypeString[] = "uint64_t";
const NetlinkAttribute::Type NetlinkU64Attribute::kType =
    NetlinkAttribute::kTypeU64;

bool NetlinkU64Attribute::InitFromValue(const ByteString& input) {
  uint64_t data;
  if (!input.CopyData(sizeof(data), &data)) {
    LOG(ERROR) << "Invalid |input| for " << id_string() << " of type "
               << datatype_string() << ": expected " << sizeof(data)
               << " bytes but only had " << input.GetLength() << ".";
    return false;
  }
  SetU64Value(data);
  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkU64Attribute::GetU64Value(uint64_t* output) const {
  if (!has_a_value_) {
    VLOG(7) << "U64 attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkU64Attribute::SetU64Value(uint64_t new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkU64Attribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  uint64_t value;
  if (!GetU64Value(&value))
    return false;
  *output = base::StringPrintf("%" PRIu64, value);
  return true;
}

ByteString NetlinkU64Attribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(
      reinterpret_cast<const unsigned char*>(&value_), sizeof(value_));
}

// NetlinkFlagAttribute

const char NetlinkFlagAttribute::kMyTypeString[] = "flag";
const NetlinkAttribute::Type NetlinkFlagAttribute::kType =
    NetlinkAttribute::kTypeFlag;

bool NetlinkFlagAttribute::InitFromValue(const ByteString& input) {
  // The existence of the parameter means it's true
  SetFlagValue(true);
  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkFlagAttribute::GetFlagValue(bool* output) const {
  if (output) {
    // The lack of the existence of the attribute implies 'false'.
    *output = (has_a_value_) ? value_ : false;
  }
  return true;
}

bool NetlinkFlagAttribute::SetFlagValue(bool new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkFlagAttribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  bool value;
  if (!GetFlagValue(&value))
    return false;
  *output = base::StringPrintf("%s", value ? "true" : "false");
  return true;
}

ByteString NetlinkFlagAttribute::Encode() const {
  if (has_a_value_ && value_) {
    return NetlinkAttribute::EncodeGeneric(nullptr, 0);
  }
  return ByteString();  // Encoding of nothing implies 'false'.
}

// NetlinkStringAttribute

const char NetlinkStringAttribute::kMyTypeString[] = "string";
const NetlinkAttribute::Type NetlinkStringAttribute::kType =
    NetlinkAttribute::kTypeString;

bool NetlinkStringAttribute::InitFromValue(const ByteString& input) {
  if (!input.GetLength()) {
    // Assume an empty string.
    SetStringValue("");
  } else {
    const char* string_ptr =
        reinterpret_cast<const char*>(input.GetConstData());
    const char* first_null_pos = reinterpret_cast<const char*>(
        memchr(string_ptr, '\0', input.GetLength()));
    if (first_null_pos == string_ptr + input.GetLength() - 1) {
      SetStringValue(string_ptr);
    } else if (first_null_pos) {
      LOG(WARNING) << "String appears to be terminated "
                   << (input.GetLength() - 1) - (first_null_pos - string_ptr)
                   << " bytes early.";
      SetStringValue(string_ptr);
    } else {
      VLOG(1) << "String is unterminated.";
      SetStringValue(std::string(string_ptr, input.GetLength()));
    }
  }

  return NetlinkAttribute::InitFromValue(input);
}

bool NetlinkStringAttribute::GetStringValue(std::string* output) const {
  if (!has_a_value_) {
    VLOG(7) << "String attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkStringAttribute::SetStringValue(const std::string& new_value) {
  value_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkStringAttribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  std::string value;
  if (!GetStringValue(&value))
    return false;

  *output = base::StringPrintf("'%s'", value.c_str());
  return true;
}

ByteString NetlinkStringAttribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(
      reinterpret_cast<const unsigned char*>(value_.c_str()),
      value_.size() + 1);
}

// SSID attribute.

bool NetlinkSsidAttribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  std::string value;
  if (!GetStringValue(&value))
    return false;

  std::string temp;
  for (const auto& chr : value) {
    // Replace '[' and ']' (in addition to non-printable characters) so that
    // it's easy to match the right substring through a non-greedy regex.
    if (chr == '[' || chr == ']' || !std::isprint(chr)) {
      base::StringAppendF(&temp, "\\x%02x", chr);
    } else {
      temp += chr;
    }
  }
  *output = base::StringPrintf("[SSID=%s]", temp.c_str());

  return true;
}

// NetlinkNestedAttribute

const char NetlinkNestedAttribute::kMyTypeString[] = "nested";
const NetlinkAttribute::Type NetlinkNestedAttribute::kType =
    NetlinkAttribute::kTypeNested;
const size_t NetlinkNestedAttribute::kArrayAttrEnumVal = 0;

NetlinkNestedAttribute::NetlinkNestedAttribute(int id, const char* id_string)
    : NetlinkAttribute(id, id_string, kType, kMyTypeString),
      value_(new AttributeList) {}

ByteString NetlinkNestedAttribute::Encode() const {
  // Encode attribute header.
  nlattr header;
  header.nla_type = id();
  header.nla_len = 0;  // Filled in at the end.
  ByteString result(reinterpret_cast<unsigned char*>(&header), sizeof(header));
  result.Resize(NLA_HDRLEN);  // Add padding after the header.

  // Encode all nested attributes.
  for (const auto& id_attribute_pair : value_->attributes_) {
    // Each attribute appends appropriate padding so it's not necessary to
    // re-add padding.
    result.Append(id_attribute_pair.second->Encode());
  }

  // Go back and fill-in the size.
  nlattr* new_header = reinterpret_cast<nlattr*>(result.GetData());
  new_header->nla_len = result.GetLength();

  return result;
}

void NetlinkNestedAttribute::Print(int log_level, int indent) const {
  VLOG(log_level) << HeaderToPrint(indent);
  value_->Print(log_level, indent + 1);
}

bool NetlinkNestedAttribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }

  // This should never be called (attribute->ToString is only called
  // from attribute->Print but NetlinkNestedAttribute::Print doesn't call
  // |ToString|.  Still, we should print something in case we got here
  // accidentally.
  LOG(WARNING) << "It is unexpected for this method to be called.";
  output->append("<Nested Attribute>");
  return true;
}

bool NetlinkNestedAttribute::InitFromValue(const ByteString& input) {
  if (!InitNestedFromValue(value_, nested_template_, input)) {
    LOG(ERROR) << "InitNestedFromValue() failed";
    return false;
  }
  has_a_value_ = true;
  return true;
}

bool NetlinkNestedAttribute::GetNestedAttributeList(
    AttributeListRefPtr* output) {
  // Not checking |has_a_value| since GetNestedAttributeList is called to get
  // a newly created AttributeList in order to have something to which to add
  // attributes.
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkNestedAttribute::ConstGetNestedAttributeList(
    AttributeListConstRefPtr* output) const {
  if (!has_a_value_) {
    LOG(ERROR) << "Attribute does not exist.";
    return false;
  }
  if (output) {
    *output = value_;
  }
  return true;
}

bool NetlinkNestedAttribute::SetNestedHasAValue() {
  has_a_value_ = true;
  return true;
}

bool NetlinkNestedAttribute::InitNestedFromValue(
    const AttributeListRefPtr& list,
    const NetlinkNestedAttribute::NestedData::NestedDataMap& templates,
    const ByteString& value) {
  if (templates.empty()) {
    LOG(ERROR) << "|templates| size is zero";
    return false;
  }
  if (templates.size() == 1 && templates.cbegin()->second.is_array) {
    return AttributeList::IterateAttributes(
        value, 0,
        base::BindRepeating(&NetlinkNestedAttribute::AddAttributeToNestedArray,
                            templates.cbegin()->second, list));
  } else {
    return AttributeList::IterateAttributes(
        value, 0,
        base::BindRepeating(&NetlinkNestedAttribute::AddAttributeToNestedMap,
                            templates, list));
  }
}

// static
bool NetlinkNestedAttribute::AddAttributeToNestedArray(
    const NetlinkNestedAttribute::NestedData& array_template,
    const AttributeListRefPtr& list,
    int id,
    const ByteString& value) {
  auto attribute_name =
      base::StringPrintf("%s_%d", array_template.attribute_name.c_str(), id);
  return AddAttributeToNestedInner(array_template, attribute_name, list, id,
                                   value);
}

// static
bool NetlinkNestedAttribute::AddAttributeToNestedMap(
    const NetlinkNestedAttribute::NestedData::NestedDataMap& templates,
    const AttributeListRefPtr& list,
    int id,
    const ByteString& value) {
  auto template_it = templates.find(id);
  if (template_it == templates.end()) {
    // No interest in this value.
    return true;
  }
  const NestedData& nested_template = template_it->second;
  return AddAttributeToNestedInner(
      nested_template, nested_template.attribute_name, list, id, value);
}

// static
bool NetlinkNestedAttribute::AddAttributeToNestedInner(
    const NetlinkNestedAttribute::NestedData& nested_template,
    const std::string& attribute_name,
    const AttributeListRefPtr& list,
    int id,
    const ByteString& value) {
  CHECK(list);
  if (!nested_template.parse_attribute.is_null()) {
    if (!nested_template.parse_attribute.Run(list.get(), id, attribute_name,
                                             value)) {
      LOG(WARNING) << "Custom attribute parser returned |false| for "
                   << attribute_name << "(" << id << ").";
      return false;
    }
    return true;
  }
  switch (nested_template.type) {
    case kTypeRaw:
      list->CreateRawAttribute(id, attribute_name.c_str());
      return list->SetRawAttributeValue(id, value);
    case kTypeU8:
      list->CreateU8Attribute(id, attribute_name.c_str());
      return list->InitAttributeFromValue(id, value);
    case kTypeU16:
      list->CreateU16Attribute(id, attribute_name.c_str());
      return list->InitAttributeFromValue(id, value);
    case kTypeU32:
      list->CreateU32Attribute(id, attribute_name.c_str());
      return list->InitAttributeFromValue(id, value);
      break;
    case kTypeU64:
      list->CreateU64Attribute(id, attribute_name.c_str());
      return list->InitAttributeFromValue(id, value);
    case kTypeFlag:
      list->CreateFlagAttribute(id, attribute_name.c_str());
      return list->SetFlagAttributeValue(id, true);
    case kTypeString:
      list->CreateStringAttribute(id, attribute_name.c_str());
      return list->InitAttributeFromValue(id, value);
    case kTypeNested: {
      if (nested_template.deeper_nesting.empty()) {
        LOG(ERROR) << "No rules for nesting " << attribute_name
                   << ". Ignoring.";
        break;
      }
      list->CreateNestedAttribute(id, attribute_name.c_str());

      // Now, handle the nested data.
      AttributeListRefPtr nested_attribute;
      if (!list->GetNestedAttributeList(id, &nested_attribute) ||
          !nested_attribute) {
        LOG(FATAL) << "Couldn't get attribute " << attribute_name
                   << " which we just created.";
        return false;
      }

      if (!InitNestedFromValue(nested_attribute, nested_template.deeper_nesting,
                               value)) {
        LOG(ERROR) << "Couldn't parse attribute " << attribute_name;
        return false;
      }
      list->SetNestedAttributeHasAValue(id);
    } break;
    default:
      LOG(ERROR) << "Discarding " << attribute_name
                 << ".  Attribute has unhandled type " << nested_template.type
                 << ".";
      break;
  }
  return true;
}

NetlinkNestedAttribute::NestedData::NestedData()
    : type(kTypeRaw), attribute_name("<UNKNOWN>"), is_array(false) {}
NetlinkNestedAttribute::NestedData::NestedData(NetlinkAttribute::Type type_arg,
                                               std::string attribute_name_arg,
                                               bool is_array_arg)
    : type(type_arg),
      attribute_name(attribute_name_arg),
      is_array(is_array_arg) {}

NetlinkNestedAttribute::NestedData::NestedData(
    NetlinkAttribute::Type type_arg,
    std::string attribute_name_arg,
    bool is_array_arg,
    const AttributeParser& parse_attribute_arg)
    : type(type_arg),
      attribute_name(attribute_name_arg),
      is_array(is_array_arg),
      parse_attribute(parse_attribute_arg) {}

// NetlinkRawAttribute

const char NetlinkRawAttribute::kMyTypeString[] = "<raw>";
const NetlinkAttribute::Type NetlinkRawAttribute::kType =
    NetlinkAttribute::kTypeRaw;

bool NetlinkRawAttribute::InitFromValue(const ByteString& input) {
  if (!NetlinkAttribute::InitFromValue(input)) {
    return false;
  }
  has_a_value_ = true;
  return true;
}

bool NetlinkRawAttribute::GetRawValue(ByteString* output) const {
  if (!has_a_value_) {
    VLOG(7) << "Raw attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  if (output) {
    *output = data_;
  }
  return true;
}

bool NetlinkRawAttribute::SetRawValue(const ByteString new_value) {
  data_ = new_value;
  has_a_value_ = true;
  return true;
}

bool NetlinkRawAttribute::ToString(std::string* output) const {
  if (!output) {
    LOG(ERROR) << "Null |output| parameter";
    return false;
  }
  if (!has_a_value_) {
    VLOG(7) << "Raw attribute " << id_string()
            << " hasn't been set to any value.";
    return false;
  }
  int total_bytes = data_.GetLength();
  const uint8_t* const_data = data_.GetConstData();

  *output = base::StringPrintf("%d bytes:", total_bytes);
  for (int i = 0; i < total_bytes; ++i) {
    base::StringAppendF(output, " %02x", const_data[i]);
  }
  return true;
}

ByteString NetlinkRawAttribute::Encode() const {
  return NetlinkAttribute::EncodeGeneric(data_.GetConstData(),
                                         data_.GetLength());
}

NetlinkAttributeGeneric::NetlinkAttributeGeneric(int id)
    : NetlinkRawAttribute(id, "unused-string") {
  base::StringAppendF(&id_string_, "<UNKNOWN ATTRIBUTE %d>", id);
}

const char* NetlinkAttributeGeneric::id_string() const {
  return id_string_.c_str();
}

}  // namespace shill
