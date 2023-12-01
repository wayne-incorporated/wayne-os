// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_OBJECT_IMPL_H_
#define CHAPS_OBJECT_IMPL_H_

#include "chaps/object.h"

#include <memory>
#include <set>
#include <string>

#include "pkcs11/cryptoki.h"

namespace chaps {

class ChapsFactory;
class ObjectPolicy;

class ObjectImpl : public Object {
 public:
  explicit ObjectImpl(ChapsFactory* factory);
  ObjectImpl(const ObjectImpl&) = delete;
  ObjectImpl& operator=(const ObjectImpl&) = delete;

  ~ObjectImpl() override;
  ObjectStage GetStage() const override;
  int GetSize() const override;
  CK_OBJECT_CLASS GetObjectClass() const override;
  bool IsTokenObject() const override;
  bool IsModifiable() const override;
  bool IsPrivate() const override;
  CK_RV FinalizeNewObject() override;
  CK_RV FinalizeCopyObject() override;
  CK_RV Copy(const Object* original) override;
  CK_RV GetAttributes(CK_ATTRIBUTE_PTR attributes,
                      int num_attributes) const override;
  CK_RV SetAttributes(const CK_ATTRIBUTE_PTR attributes,
                      int num_attributes) override;
  bool IsAttributePresent(CK_ATTRIBUTE_TYPE type) const override;
  bool GetAttributeBool(CK_ATTRIBUTE_TYPE type,
                        bool default_value) const override;
  void SetAttributeBool(CK_ATTRIBUTE_TYPE type, bool value) override;
  CK_ULONG GetAttributeInt(CK_ATTRIBUTE_TYPE type,
                           CK_ULONG default_value) const override;
  void SetAttributeInt(CK_ATTRIBUTE_TYPE type, CK_ULONG value) override;
  std::string GetAttributeString(CK_ATTRIBUTE_TYPE type) const override;
  void SetAttributeString(CK_ATTRIBUTE_TYPE type,
                          const std::string& value) override;
  void RemoveAttribute(CK_ATTRIBUTE_TYPE type) override;
  const AttributeMap* GetAttributeMap() const override;
  bool OnLoad() override;
  int handle() const override { return handle_; }
  void set_handle(int handle) override { handle_ = handle; }
  int store_id() const override { return store_id_; }
  void set_store_id(int store_id) override { store_id_ = store_id; }

 private:
  ChapsFactory* factory_;
  ObjectStage stage_;
  AttributeMap attributes_;
  // Tracks attributes which have been set by the user.
  std::set<CK_ATTRIBUTE_TYPE> external_attributes_;
  std::unique_ptr<ObjectPolicy> policy_;
  int handle_;
  int store_id_;

  bool SetPolicyByClass();
};

}  // namespace chaps

#endif  // CHAPS_OBJECT_IMPL_H_
