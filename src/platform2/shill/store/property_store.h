// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_PROPERTY_STORE_H_
#define SHILL_STORE_PROPERTY_STORE_H_

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/strings/string_piece.h>
#include <brillo/any.h>
#include <brillo/variant_dictionary.h>

#include "shill/store/accessor_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;

class PropertyStore {
 public:
  using PropertyChangeCallback =
      base::RepeatingCallback<void(base::StringPiece)>;
  PropertyStore();
  explicit PropertyStore(PropertyChangeCallback property_change_callback);
  PropertyStore(const PropertyStore&) = delete;
  PropertyStore& operator=(const PropertyStore&) = delete;

  ~PropertyStore();

  bool Contains(base::StringPiece property) const;

  // Setting properties using brillo::Any variant type.
  void SetAnyProperty(base::StringPiece name,
                      const brillo::Any& value,
                      Error* error);
  void SetProperties(const brillo::VariantDictionary& in, Error* error);

  // Retrieve all properties and store them in a brillo::VariantDictionary
  // (std::map<std::string, brillo::Any>).
  bool GetProperties(brillo::VariantDictionary* out, Error* error) const;

  // Methods to allow the getting of properties stored in the referenced
  // |store_| by name. Upon success, these methods return true and return the
  // property value in |value|. Upon failure, they return false and
  // leave |value| untouched.
  bool GetBoolProperty(base::StringPiece name, bool* value, Error* error) const;
  bool GetInt16Property(base::StringPiece name,
                        int16_t* value,
                        Error* error) const;
  bool GetInt32Property(base::StringPiece name,
                        int32_t* value,
                        Error* error) const;
  bool GetKeyValueStoreProperty(base::StringPiece name,
                                KeyValueStore* value,
                                Error* error) const;
  bool GetKeyValueStoresProperty(base::StringPiece name,
                                 KeyValueStores* value,
                                 Error* error) const;
  bool GetStringProperty(base::StringPiece name,
                         std::string* value,
                         Error* error) const;
  bool GetStringmapProperty(base::StringPiece name,
                            Stringmap* values,
                            Error* error) const;
  bool GetStringmapsProperty(base::StringPiece name,
                             Stringmaps* values,
                             Error* error) const;
  bool GetStringsProperty(base::StringPiece name,
                          Strings* values,
                          Error* error) const;
  bool GetUint8Property(base::StringPiece name,
                        uint8_t* value,
                        Error* error) const;
  bool GetByteArrayProperty(base::StringPiece name,
                            ByteArray* value,
                            Error* error) const;
  bool GetUint16Property(base::StringPiece name,
                         uint16_t* value,
                         Error* error) const;
  bool GetUint16sProperty(base::StringPiece name,
                          Uint16s* value,
                          Error* error) const;
  bool GetUint32Property(base::StringPiece name,
                         uint32_t* value,
                         Error* error) const;
  bool GetUint64Property(base::StringPiece name,
                         uint64_t* value,
                         Error* error) const;
  bool GetRpcIdentifierProperty(base::StringPiece name,
                                RpcIdentifier* value,
                                Error* error) const;

  // Methods to allow the setting, by name, of properties stored in this object.
  // The property names are declared in chromeos/dbus/service_constants.h,
  // so that they may be shared with libcros.
  // If the property is successfully changed, these methods leave |error|
  // untouched.
  // If the property is unchanged because it already has the desired value,
  // these methods leave |error| untouched.
  // If the property change fails, these methods update |error|. However,
  // updating |error| is skipped if |error| is NULL.
  void SetBoolProperty(base::StringPiece name, bool value, Error* error);

  void SetInt16Property(base::StringPiece name, int16_t value, Error* error);

  void SetInt32Property(base::StringPiece name, int32_t value, Error* error);

  void SetKeyValueStoreProperty(base::StringPiece name,
                                const KeyValueStore& value,
                                Error* error);

  void SetKeyValueStoresProperty(base::StringPiece name,
                                 const KeyValueStores& value,
                                 Error* error);

  void SetStringProperty(base::StringPiece name,
                         const std::string& value,
                         Error* error);

  void SetStringmapProperty(base::StringPiece name,
                            const std::map<std::string, std::string>& values,
                            Error* error);

  void SetStringmapsProperty(
      base::StringPiece name,
      const std::vector<std::map<std::string, std::string>>& values,
      Error* error);

  void SetStringsProperty(base::StringPiece name,
                          const std::vector<std::string>& values,
                          Error* error);

  void SetUint8Property(base::StringPiece name, uint8_t value, Error* error);

  void SetByteArrayProperty(base::StringPiece name,
                            const ByteArray& value,
                            Error* error);

  void SetUint16Property(base::StringPiece name, uint16_t value, Error* error);

  void SetUint16sProperty(base::StringPiece name,
                          const std::vector<uint16_t>& value,
                          Error* error);

  void SetUint32Property(base::StringPiece name, uint32_t value, Error* error);

  void SetUint64Property(base::StringPiece name, uint64_t value, Error* error);

  void SetRpcIdentifierProperty(base::StringPiece name,
                                const RpcIdentifier& value,
                                Error* error);

  // Clearing a property resets it to its "factory" value. This value
  // is generally the value that it (the property) had when it was
  // registered with PropertyStore.
  //
  // The exception to this rule is write-only derived properties. For
  // such properties, the property owner explicitly provides a
  // "factory" value at registration time. This is necessary because
  // PropertyStore can't read the current value at registration time.
  //
  // |name| is the key used to access the property. If the property
  // cannot be cleared, |error| is set, and the method returns false.
  // Otherwise, |error| is unchanged, and the method returns true.
  bool ClearProperty(base::StringPiece name, Error* error);

  // Methods for registering a property.
  //
  // It is permitted to re-register a property (in which case the old
  // binding is forgotten). However, the newly bound object must be of
  // the same type.
  //
  // Note that types do not encode read-write permission.  Hence, it
  // is possible to change permissions by rebinding a property to the
  // same object.
  //
  // (Corollary of the rebinding-to-same-type restriction: a
  // PropertyStore cannot hold two properties of the same name, but
  // differing types.)
  void RegisterBool(base::StringPiece name, bool* prop);
  void RegisterConstBool(base::StringPiece name, const bool* prop);
  void RegisterWriteOnlyBool(base::StringPiece name, bool* prop);
  void RegisterInt16(base::StringPiece name, int16_t* prop);
  void RegisterConstInt16(base::StringPiece name, const int16_t* prop);
  void RegisterWriteOnlyInt16(base::StringPiece name, int16_t* prop);
  void RegisterInt32(base::StringPiece name, int32_t* prop);
  void RegisterConstInt32(base::StringPiece name, const int32_t* prop);
  void RegisterWriteOnlyInt32(base::StringPiece name, int32_t* prop);
  void RegisterUint32(base::StringPiece name, uint32_t* prop);
  void RegisterConstUint32(base::StringPiece name, const uint32_t* prop);
  void RegisterUint64(base::StringPiece name, uint64_t* prop);
  void RegisterString(base::StringPiece name, std::string* prop);
  void RegisterConstString(base::StringPiece name, const std::string* prop);
  void RegisterWriteOnlyString(base::StringPiece name, std::string* prop);
  void RegisterStringmap(base::StringPiece name, Stringmap* prop);
  void RegisterConstStringmap(base::StringPiece name, const Stringmap* prop);
  void RegisterWriteOnlyStringmap(base::StringPiece name, Stringmap* prop);
  void RegisterStringmaps(base::StringPiece name, Stringmaps* prop);
  void RegisterConstStringmaps(base::StringPiece name, const Stringmaps* prop);
  void RegisterWriteOnlyStringmaps(base::StringPiece name, Stringmaps* prop);
  void RegisterStrings(base::StringPiece name, Strings* prop);
  void RegisterConstStrings(base::StringPiece name, const Strings* prop);
  void RegisterWriteOnlyStrings(base::StringPiece name, Strings* prop);
  void RegisterUint8(base::StringPiece name, uint8_t* prop);
  void RegisterConstUint8(base::StringPiece name, const uint8_t* prop);
  void RegisterWriteOnlyUint8(base::StringPiece name, uint8_t* prop);
  void RegisterUint16(base::StringPiece name, uint16_t* prop);
  void RegisterUint16s(base::StringPiece name, Uint16s* prop);
  void RegisterConstUint16(base::StringPiece name, const uint16_t* prop);
  void RegisterConstUint16s(base::StringPiece name, const Uint16s* prop);
  void RegisterWriteOnlyUint16(base::StringPiece name, uint16_t* prop);
  void RegisterByteArray(base::StringPiece name, ByteArray* prop);
  void RegisterConstByteArray(base::StringPiece name, const ByteArray* prop);
  void RegisterWriteOnlyByteArray(base::StringPiece name, ByteArray* prop);
  void RegisterKeyValueStore(base::StringPiece name, KeyValueStore* prop);
  void RegisterConstKeyValueStore(base::StringPiece name,
                                  const KeyValueStore* prop);
  void RegisterKeyValueStores(base::StringPiece name, KeyValueStores* prop);
  void RegisterConstKeyValueStores(base::StringPiece name,
                                   const KeyValueStores* prop);

  void RegisterDerivedBool(base::StringPiece name, BoolAccessor accessor);
  void RegisterDerivedInt32(base::StringPiece name, Int32Accessor accessor);
  void RegisterDerivedKeyValueStore(base::StringPiece name,
                                    KeyValueStoreAccessor accessor);
  void RegisterDerivedKeyValueStores(base::StringPiece name,
                                     KeyValueStoresAccessor accessor);
  void RegisterDerivedRpcIdentifier(base::StringPiece name,
                                    RpcIdentifierAccessor acc);
  void RegisterDerivedRpcIdentifiers(base::StringPiece name,
                                     RpcIdentifiersAccessor accessor);
  void RegisterDerivedString(base::StringPiece name, StringAccessor accessor);
  void RegisterDerivedStringmap(base::StringPiece name,
                                StringmapAccessor accessor);
  void RegisterDerivedStringmaps(base::StringPiece name,
                                 StringmapsAccessor accessor);
  void RegisterDerivedStrings(base::StringPiece name, StringsAccessor accessor);
  void RegisterDerivedUint16(base::StringPiece name, Uint16Accessor accessor);
  void RegisterDerivedUint64(base::StringPiece name, Uint64Accessor accessor);
  void RegisterDerivedUint16s(base::StringPiece name, Uint16sAccessor accessor);
  void RegisterDerivedByteArray(base::StringPiece name,
                                ByteArrayAccessor accessor);

 private:
  template <class V>
  bool GetProperty(base::StringPiece name,
                   V* value,
                   Error* error,
                   const AccessorMap<V>& collection,
                   base::StringPiece value_type_english) const;

  template <class V>
  bool SetProperty(base::StringPiece name,
                   const V& value,
                   Error* error,
                   AccessorMap<V>* collection,
                   base::StringPiece value_type_english);

  // These are std::maps instead of something cooler because the common
  // operation is iterating through them and returning all properties.
  std::map<std::string, BoolAccessor, std::less<>> bool_properties_;
  std::map<std::string, Int16Accessor, std::less<>> int16_properties_;
  std::map<std::string, Int32Accessor, std::less<>> int32_properties_;
  std::map<std::string, KeyValueStoreAccessor, std::less<>>
      key_value_store_properties_;
  std::map<std::string, KeyValueStoresAccessor, std::less<>>
      key_value_stores_properties_;
  std::map<std::string, RpcIdentifierAccessor, std::less<>>
      rpc_identifier_properties_;
  std::map<std::string, RpcIdentifiersAccessor, std::less<>>
      rpc_identifiers_properties_;
  std::map<std::string, StringAccessor, std::less<>> string_properties_;
  std::map<std::string, StringmapAccessor, std::less<>> stringmap_properties_;
  std::map<std::string, StringmapsAccessor, std::less<>> stringmaps_properties_;
  std::map<std::string, StringsAccessor, std::less<>> strings_properties_;
  std::map<std::string, Uint8Accessor, std::less<>> uint8_properties_;
  std::map<std::string, ByteArrayAccessor, std::less<>> bytearray_properties_;
  std::map<std::string, Uint16Accessor, std::less<>> uint16_properties_;
  std::map<std::string, Uint16sAccessor, std::less<>> uint16s_properties_;
  std::map<std::string, Uint32Accessor, std::less<>> uint32_properties_;
  std::map<std::string, Uint64Accessor, std::less<>> uint64_properties_;

  PropertyChangeCallback property_changed_callback_;
};

}  // namespace shill

#endif  // SHILL_STORE_PROPERTY_STORE_H_
