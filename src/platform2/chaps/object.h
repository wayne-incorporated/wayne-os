// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_H_
#define CHAPS_OBJECT_H_

#include <map>
#include <string>

#include "pkcs11/cryptoki.h"

namespace chaps {

typedef std::map<CK_ATTRIBUTE_TYPE, std::string> AttributeMap;

// Object policies can differ depending on the stage an object is at in its
// lifecycle.
enum ObjectStage {
  kCreate,  // The object is being created.
  kCopy,    // The object is being created as a copy of another object.
  kModify,  // The object already exists.
  kNumObjectStages
};

// Object is the interface for a PKCS #11 object.  This component manages all
// object attributes and provides query and modify access to attributes
// according to the current object policy.
class Object {
 public:
  virtual ~Object() {}
  virtual ObjectStage GetStage() const = 0;
  // Returns a general indicator of the object's size. This size will be at
  // least as large as the combined size of the object's attribute values.
  virtual int GetSize() const = 0;
  // Returns the object class. If the CKA_CLASS attribute does not exist, the
  // return value is undefined.
  virtual CK_OBJECT_CLASS GetObjectClass() const = 0;
  // Returns the value of the CKA_TOKEN attribute.
  virtual bool IsTokenObject() const = 0;
  // Returns the value of the CKA_MODIFIABLE attribute.
  virtual bool IsModifiable() const = 0;
  // Returns the value of the CKA_PRIVATE attribute.
  virtual bool IsPrivate() const = 0;
  // Performs final tasks required when creating a new object:
  // - Assigns a policy.
  // - Validates that attributes set by the user are allowed to be set.
  // - Validates attributes for consistency and completeness.
  // - Set default values for attributes, if necessary.
  // - Move the object into the kModify stage.
  virtual CK_RV FinalizeNewObject() = 0;
  // This is called when all changes to a copied object is done.
  virtual CK_RV FinalizeCopyObject() = 0;
  // Copies attributes and policy from another object.
  virtual CK_RV Copy(const Object* original) = 0;
  // Provides PKCS #11 attribute values according to the semantics described in
  // PKCS #11 v2.20: 11.7 - C_GetAttributeValue (p. 133). If a policy exists it
  // will be enforced.
  virtual CK_RV GetAttributes(CK_ATTRIBUTE_PTR attributes,
                              int num_attributes) const = 0;
  // Sets object attributes from a list of PKCS #11 attribute values according
  // to the semantics described in PKCS #11 v2.20: 11.7 - C_SetAttributeValue
  // (p. 135). If a policy exists it will be enforced.
  virtual CK_RV SetAttributes(const CK_ATTRIBUTE_PTR attributes,
                              int num_attributes) = 0;
  // Returns true if the a value for the attribute exists.
  virtual bool IsAttributePresent(CK_ATTRIBUTE_TYPE type) const = 0;

  // Note:
  // Policy will not be enforced for the following methods. These methods are
  // strictly for use within the PKCS #11 boundary. This allows Chaps code to
  // view and modify attributes that cannot be viewed or modified from outside
  // the PKCS #11 boundary. For example, setting CKA_LOCAL to true when a key is
  // generated.

  // Queries a boolean attribute. If the attribute does not exist or is not
  // valid, 'default_value' is returned.
  virtual bool GetAttributeBool(CK_ATTRIBUTE_TYPE type,
                                bool default_value) const = 0;
  // Sets a boolean attribute. Policies will not be enforced (e.g. CKA_LOCAL can
  // be set using this method even though a user cannot set this attribute).
  virtual void SetAttributeBool(CK_ATTRIBUTE_TYPE type, bool value) = 0;
  // Queries an integral attribute. If the attribute does not exist or is not
  // valid, 'default_value' is returned.
  virtual CK_ULONG GetAttributeInt(CK_ATTRIBUTE_TYPE type,
                                   CK_ULONG default_value) const = 0;
  // Sets an integral attribute. Policies will not be enforced.
  virtual void SetAttributeInt(CK_ATTRIBUTE_TYPE type, CK_ULONG value) = 0;
  // Queries an attribute value as a string.
  virtual std::string GetAttributeString(CK_ATTRIBUTE_TYPE type) const = 0;
  // Sets an attribute as a string. Policies will not be enforced.
  virtual void SetAttributeString(CK_ATTRIBUTE_TYPE type,
                                  const std::string& value) = 0;
  // Removes an attribute. This is not the same as setting an attribute value to
  // the empty string.
  virtual void RemoveAttribute(CK_ATTRIBUTE_TYPE type) = 0;
  // Provides a read-only map of all existing attributes.
  virtual const AttributeMap* GetAttributeMap() const = 0;
  // This should be called after an object is loaded from disk. If this returns
  // false, then object loading should be considered as failed.
  virtual bool OnLoad() = 0;
  // Get / set handle as seen by PKCS #11 clients.
  virtual int handle() const = 0;
  virtual void set_handle(int handle) = 0;
  // Get / set an identifier as designated by a store.
  virtual int store_id() const = 0;
  virtual void set_store_id(int store_id) = 0;
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_H_
