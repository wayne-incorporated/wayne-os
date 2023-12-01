// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_CONTROL_NETLINK_ATTRIBUTE_H_
#define SHILL_NET_CONTROL_NETLINK_ATTRIBUTE_H_

#include "shill/net/netlink_attribute.h"

namespace shill {

// Control.

class ControlAttributeFamilyId : public NetlinkU16Attribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeFamilyId() : NetlinkU16Attribute(kName, kNameString) {}
  ControlAttributeFamilyId(const ControlAttributeFamilyId&) = delete;
  ControlAttributeFamilyId& operator=(const ControlAttributeFamilyId&) = delete;
};

class ControlAttributeFamilyName : public NetlinkStringAttribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeFamilyName() : NetlinkStringAttribute(kName, kNameString) {}
  ControlAttributeFamilyName(const ControlAttributeFamilyName&) = delete;
  ControlAttributeFamilyName& operator=(const ControlAttributeFamilyName&) =
      delete;
};

class ControlAttributeVersion : public NetlinkU32Attribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeVersion() : NetlinkU32Attribute(kName, kNameString) {}
  ControlAttributeVersion(const ControlAttributeVersion&) = delete;
  ControlAttributeVersion& operator=(const ControlAttributeVersion&) = delete;
};

class ControlAttributeHdrSize : public NetlinkU32Attribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeHdrSize() : NetlinkU32Attribute(kName, kNameString) {}
  ControlAttributeHdrSize(const ControlAttributeHdrSize&) = delete;
  ControlAttributeHdrSize& operator=(const ControlAttributeHdrSize&) = delete;
};

class ControlAttributeMaxAttr : public NetlinkU32Attribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeMaxAttr() : NetlinkU32Attribute(kName, kNameString) {}
  ControlAttributeMaxAttr(const ControlAttributeMaxAttr&) = delete;
  ControlAttributeMaxAttr& operator=(const ControlAttributeMaxAttr&) = delete;
};

class ControlAttributeAttrOps : public NetlinkNestedAttribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeAttrOps();
  ControlAttributeAttrOps(const ControlAttributeAttrOps&) = delete;
  ControlAttributeAttrOps& operator=(const ControlAttributeAttrOps&) = delete;
};

class ControlAttributeMcastGroups : public NetlinkNestedAttribute {
 public:
  static const int kName;
  static const char kNameString[];
  ControlAttributeMcastGroups();
  ControlAttributeMcastGroups(const ControlAttributeMcastGroups&) = delete;
  ControlAttributeMcastGroups& operator=(const ControlAttributeMcastGroups&) =
      delete;
};

}  // namespace shill

#endif  // SHILL_NET_CONTROL_NETLINK_ATTRIBUTE_H_
