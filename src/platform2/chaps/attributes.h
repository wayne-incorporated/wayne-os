// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_ATTRIBUTES_H_
#define CHAPS_ATTRIBUTES_H_

#include <memory>
#include <string>
#include <vector>

#include "pkcs11/cryptoki.h"

namespace chaps {

// This class encapsulates an array of CK_ATTRIBUTEs and provides serialization.
class EXPORT_SPEC Attributes {
 public:
  // This constructor initializes with a NULL array.
  Attributes();
  // This constructor does not take ownership of the array.  I.e. No memory
  // deallocation will be performed when the object destructs.
  Attributes(CK_ATTRIBUTE_PTR attributes, CK_ULONG num_attributes);
  Attributes(const Attributes&) = delete;
  Attributes& operator=(const Attributes&) = delete;

  virtual ~Attributes();
  CK_ATTRIBUTE_PTR attributes() const { return attributes_; }
  CK_ULONG num_attributes() const { return num_attributes_; }
  // This method serializes the current array of attributes.
  virtual bool Serialize(std::vector<uint8_t>* serialized_attributes) const;
  // This method parses a serialized array of attributes into a new CK_ATTRIBUTE
  // array.  Any previous array will be deleted if necessary and discarded.
  virtual bool Parse(const std::vector<uint8_t>& serialized_attributes);
  // This method parses a serialized array of attributes and fills the current
  // attribute array with the values.  No memory will be allocated.  The number
  // and type of attributes parsed must match exactly the number and type of
  // attributes in the current array.  Also, the current array must have all
  // necessary memory allocated to receive parsed values.
  virtual bool ParseAndFill(const std::vector<uint8_t>& serialized_attributes);

  // This method determines if a given attribute holds a nested attribute array.
  static bool IsAttributeNested(CK_ATTRIBUTE_TYPE type);

 private:
  // Frees all allocated memory blocks by |AllocateCkAttributeArray| and
  // |AllocateCkByteArray|. Also resets |attributes_| and |num_attributes_| if
  // |attributes_| is also allocated by |AllocateCkAttributeArray|.
  void Free();
  // Allocates memory for |num| |CK_ATTRIBUTE|s, records the result in
  // |allocated_attribute_arrays_| before returns it.
  CK_ATTRIBUTE_PTR AllocateCkAttributeArray(size_t num);
  // Allocates memory for |CK_BYTE|s in size of |size|, records the result in
  // |allocated_byte_arrays_| before returns it.
  CK_BYTE_PTR AllocateCkByteArray(size_t size);
  bool SerializeInternal(CK_ATTRIBUTE_PTR attributes,
                         CK_ULONG num_attributes,
                         bool is_nesting_allowed,
                         std::string* serialized_attributes) const;
  bool ParseInternal(const std::string& serialized_attributes,
                     bool is_nesting_allowed,
                     CK_ATTRIBUTE_PTR* attributes,
                     CK_ULONG* num_attributes);
  bool ParseAndFillInternal(const std::string& serialized_attributes,
                            bool is_nesting_allowed,
                            CK_ATTRIBUTE_PTR attributes,
                            CK_ULONG num_attributes);

  static CK_ULONG IntToValueLength(int i);
  static std::string AttributeValueToString(const CK_ATTRIBUTE& attributes);

  // The array being managed (i.e. the 'current' array).
  CK_ATTRIBUTE_PTR attributes_;
  CK_ULONG num_attributes_;

  // A container that keeps track of all allocated attribute arrays.
  std::vector<std::unique_ptr<CK_ATTRIBUTE[]>> allocated_attribute_arrays_;
  // A container that keeps track of all allocated byte arrays.
  std::vector<std::unique_ptr<CK_BYTE[]>> allocated_byte_arrays_;
};

}  // namespace chaps

#endif  // CHAPS_ATTRIBUTES_H_
