// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/attribute_list.h"

#include <ctype.h>
#include <linux/nl80211.h>

#include <iomanip>

#include <base/containers/contains.h>
#include <base/logging.h>

#include "shill/net/netlink_attribute.h"

namespace shill {

AttributeList::AttributeList() = default;

AttributeList::~AttributeList() = default;

bool AttributeList::CreateAttribute(int id,
                                    AttributeList::NewFromIdMethod factory) {
  if (base::Contains(attributes_, id)) {
    VLOG(7) << "Trying to re-add attribute " << id << ", not overwriting";
    return true;
  }
  attributes_[id] = factory.Run(id);
  return true;
}

bool AttributeList::CreateControlAttribute(int id) {
  return CreateAttribute(
      id, base::BindRepeating(&NetlinkAttribute::NewControlAttributeFromId));
}

bool AttributeList::CreateNl80211Attribute(
    int id, NetlinkMessage::MessageContext context) {
  return CreateAttribute(
      id, base::BindRepeating(&NetlinkAttribute::NewNl80211AttributeFromId,
                              context));
}

bool AttributeList::CreateAndInitAttribute(
    const AttributeList::NewFromIdMethod& factory,
    int id,
    const ByteString& value) {
  if (!CreateAttribute(id, factory)) {
    return false;
  }
  return InitAttributeFromValue(id, value);
}

bool AttributeList::InitAttributeFromValue(int id, const ByteString& value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->InitFromValue(value);
}

void AttributeList::Print(int log_level, int indent) const {
  for (const auto& id_attribute_pair : attributes_) {
    id_attribute_pair.second->Print(log_level, indent);
  }
}

// static
bool AttributeList::IterateAttributes(
    const ByteString& payload,
    size_t offset,
    const AttributeList::AttributeMethod& method) {
  // Nothing to iterate over.
  if (payload.IsEmpty())
    return true;

  // Invalid offset.
  if (payload.GetLength() < NLA_ALIGN(offset)) {
    LOG(ERROR) << "Attribute offset " << offset
               << " was larger than payload length " << payload.GetLength();
    return false;
  }

  const unsigned char* ptr = payload.GetConstData() + NLA_ALIGN(offset);
  const unsigned char* end = payload.GetConstData() + payload.GetLength();
  // TODO(b/206049224) Remove all pointer arithmetic in favor of direct offset
  // comparisons to prevent bugs caused by pointer address numeric overflow.
  while (ptr + sizeof(nlattr) <= end) {
    const nlattr* attribute = reinterpret_cast<const nlattr*>(ptr);
    if (attribute->nla_len < sizeof(*attribute) ||
        ptr + attribute->nla_len > end) {
      LOG(ERROR) << "Malformed nla attribute indicates length "
                 << attribute->nla_len << ".  " << (end - ptr - NLA_HDRLEN)
                 << " bytes remain in buffer.  "
                 << "Error occurred at offset "
                 << (ptr - payload.GetConstData()) << ".";
      return false;
    }
    ByteString value;
    if (attribute->nla_len > NLA_HDRLEN) {
      value = ByteString(ptr + NLA_HDRLEN, attribute->nla_len - NLA_HDRLEN);
    }
    if (!method.Run(attribute->nla_type, value)) {
      return false;
    }
    ptr += NLA_ALIGN(attribute->nla_len);
  }
  if (ptr < end) {
    LOG(INFO) << "Decode left " << (end - ptr) << " unparsed bytes.";
  }
  return true;
}

bool AttributeList::Decode(const ByteString& payload,
                           size_t offset,
                           const AttributeList::NewFromIdMethod& factory) {
  return IterateAttributes(
      payload, offset,
      base::BindRepeating(&AttributeList::CreateAndInitAttribute,
                          base::Unretained(this), factory));
}

ByteString AttributeList::Encode() const {
  ByteString result;
  for (const auto& id_attribute_pair : attributes_) {
    result.Append(id_attribute_pair.second->Encode());
  }
  return result;
}

// U8 Attribute.

bool AttributeList::GetU8AttributeValue(int id, uint8_t* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetU8Value(value);
}

bool AttributeList::CreateU8Attribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkU8Attribute>(id, id_string);
  return true;
}

bool AttributeList::SetU8AttributeValue(int id, uint8_t value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetU8Value(value);
}

// U16 Attribute.

bool AttributeList::GetU16AttributeValue(int id, uint16_t* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetU16Value(value);
}

bool AttributeList::CreateU16Attribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkU16Attribute>(id, id_string);
  return true;
}

bool AttributeList::SetU16AttributeValue(int id, uint16_t value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetU16Value(value);
}

// U32 Attribute.

bool AttributeList::GetU32AttributeValue(int id, uint32_t* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetU32Value(value);
}

bool AttributeList::CreateU32Attribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkU32Attribute>(id, id_string);
  return true;
}

bool AttributeList::SetU32AttributeValue(int id, uint32_t value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetU32Value(value);
}

// U64 Attribute.

bool AttributeList::GetU64AttributeValue(int id, uint64_t* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetU64Value(value);
}

bool AttributeList::CreateU64Attribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkU64Attribute>(id, id_string);
  return true;
}

bool AttributeList::SetU64AttributeValue(int id, uint64_t value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetU64Value(value);
}

// Flag Attribute.

bool AttributeList::GetFlagAttributeValue(int id, bool* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetFlagValue(value);
}

bool AttributeList::CreateFlagAttribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkFlagAttribute>(id, id_string);
  return true;
}

bool AttributeList::SetFlagAttributeValue(int id, bool value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetFlagValue(value);
}

bool AttributeList::IsFlagAttributeTrue(int id) const {
  bool flag;
  if (!GetFlagAttributeValue(id, &flag)) {
    return false;
  }
  return flag;
}

// String Attribute.

bool AttributeList::GetStringAttributeValue(int id, std::string* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetStringValue(value);
}

bool AttributeList::CreateStringAttribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkStringAttribute>(id, id_string);
  return true;
}

bool AttributeList::CreateSsidAttribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkSsidAttribute>(id, id_string);
  return true;
}

bool AttributeList::SetStringAttributeValue(int id, const std::string& value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetStringValue(value);
}

// Nested Attribute.

bool AttributeList::GetNestedAttributeList(int id, AttributeListRefPtr* value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->GetNestedAttributeList(value);
}

bool AttributeList::ConstGetNestedAttributeList(
    int id, AttributeListConstRefPtr* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->ConstGetNestedAttributeList(value);
}

bool AttributeList::SetNestedAttributeHasAValue(int id) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetNestedHasAValue();
}

bool AttributeList::CreateNestedAttribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkNestedAttribute>(id, id_string);
  return true;
}

// Raw Attribute.

bool AttributeList::GetRawAttributeValue(int id, ByteString* output) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;

  ByteString raw_value;

  if (!attribute->GetRawValue(&raw_value))
    return false;

  if (output) {
    *output = raw_value;
  }
  return true;
}

bool AttributeList::SetRawAttributeValue(int id, ByteString value) {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;
  return attribute->SetRawValue(value);
}

bool AttributeList::CreateRawAttribute(int id, const char* id_string) {
  if (base::Contains(attributes_, id)) {
    LOG(ERROR) << "Trying to re-add attribute: " << id;
    return false;
  }
  attributes_[id] = std::make_unique<NetlinkRawAttribute>(id, id_string);
  return true;
}

bool AttributeList::GetAttributeAsString(int id, std::string* value) const {
  NetlinkAttribute* attribute = GetAttribute(id);
  if (!attribute)
    return false;

  return attribute->ToString(value);
}

NetlinkAttribute* AttributeList::GetAttribute(int id) const {
  AttributeMap::const_iterator i = attributes_.find(id);
  if (i == attributes_.end()) {
    return nullptr;
  }
  return i->second.get();
}

int AttributeIdIterator::GetType() const {
  return iter_->second->datatype();
}

}  // namespace shill
