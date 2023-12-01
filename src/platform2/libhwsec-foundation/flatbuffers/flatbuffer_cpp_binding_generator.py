#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A C++ binding code generator for flatbuffers schema.

This generator generates four kinds of files form flatbuffers schema:
1. Structure Definition Header (<Name>.h)
    The C++ structure definition.
    You only need to include this file in most of the case.

    Note: the trailing namespace "_serialized_" is omitted in this file,
    in order to avoid conflicts with flatc-generated symbols in
    "<Name>_generated.h".

2. Flatbuffers Structure Converter Header (<Name>_flatbuffer.h)
    The template converter for C++ structure and flatbuffers object.
    You shouldn't include this file in most of the case.

3. Structure Testing Utils Header (<Name>_test_utils.h)
    This file containing the compare operators for the generated structure.
    You should only include this file for testing purpose.

4. Structure Serializer Implementation (<Name>.cc)
    The implementation of serializer and deserializer.
    Your program should link to this file.

This generator introduces three new custom attributes in the schema:
1. secure
  Adding this attribute to the table will let the [ubyte] field using
  SecureBlob. And let the serialization functions using SecureBlob.

  e.g.
    AuthBlockState (serializable, secure) ->
      std::optional<Blob> Serialize() const;
      static std::optional<AuthBlockState> Deserialize(const Blob&);

    AuthBlockState (serializable) ->
      std::optional<SecureBlob> Serialize() const;
      static std::optional<AuthBlockState> Deserialize(const SecureBlob&);

    And adding this attribute to the union will ensure all internal table must
    be secure.

2. optional
  Adding optional attribute to the field of table will let the generator
  generate std::optional in the generated code.

  If the type of field is scalar type, you must add =null as the default value,
  and adding =null to the scalar will implicit let the field become optional.

  e.g.
    [ubyte] -> Blob
    [ubyte] (optional) -> std::optional<Blob>
    [ubyte] (optional, secure) -> std::optional<SecureBlob>
    uint -> "Failed to generate"
    uint = null -> std::optional<uint32_t>
    uint = null (optional) -> std::optional<uint32_t>
    uint(optional) -> "Failed to generate"

3. serializable
  Adding this attribute to table will introduce serialization functions to the
  structure.

  If the table has any possibility to contain secure field(even in the nested
  structure), you must explicit add secure attribute to the table.

  And the serializable table must be the root_type of the schema file.
  Note: We should remove this attribute after flatbuffer reflection API support
  splitting files.
"""

import argparse
from datetime import date
from functools import lru_cache
import logging
import os
import re
from subprocess import PIPE
from subprocess import run
import sys

# The following imports will be available in the build system.
# pylint: disable=import-error,no-name-in-module
from jinja2 import Template
from reflection.BaseType import BaseType
from reflection.Schema import Schema


_SERIALIZED_NAMESPACE = "_serialized_"

_SERIALIZABLE_ATTRIBUTE = "serializable"
_SECURE_ATTRIBUTE = "secure"
_OPTIONAL_ATTRIBUTE = "optional"

_CPP_OPTIONAL_TYPE = "std::optional"
_CPP_VARIANT_TYPE = "std::variant"
_CPP_VISIT = "std::visit"
_CPP_MONOSTATE_TYPE = "std::monostate"
_CPP_NULLOPT = "std::nullopt"

_CONVERTER_NAMESPACE = tuple(["hwsec_foundation"])

_VECTOR_TEMPLATE = Template("std::vector<{{inner_type}}>")
_ARRAY_TEMPLATE = Template("{{inner_type}}[{{size}}]")
_OPTIONAL_TEMPLATE = Template(
    "%(optional_type)s<{{inner_type}}>"
    % {
        "optional_type": _CPP_OPTIONAL_TYPE,
    }
)

# The prefix to export the serializer symbol, so we can export the serializer
# in the shared library.
_EXPORT_ATTRIBUTE = '__attribute__((visibility("default")))'

_ENUM_TOPOSORT_TYPE = 0
_OBJECT_TOPOSORT_TYPE = 1

_SCALAR_SET = set(
    (
        BaseType.Bool,
        BaseType.Byte,
        BaseType.UByte,
        BaseType.Short,
        BaseType.UShort,
        BaseType.Int,
        BaseType.UInt,
        BaseType.Long,
        BaseType.ULong,
        BaseType.Float,
        BaseType.Double,
    )
)

_BASE_TYPE_STRING = {
    BaseType.Bool: "bool",
    BaseType.Byte: "int8_t",
    BaseType.UByte: "uint8_t",
    BaseType.Short: "int16_t",
    BaseType.UShort: "uint16_t",
    BaseType.Int: "int32_t",
    BaseType.UInt: "uint32_t",
    BaseType.Long: "int64_t",
    BaseType.ULong: "uint64_t",
    BaseType.Float: "float",
    BaseType.Double: "double",
    BaseType.String: "std::string",
}

_COPYRIGHT_HEADER = Template(
    """\
// Copyright {{ year }} The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED.
// Generated with command:
// {{ cmd }}
"""
).render(year=date.today().year, cmd=" ".join(sys.argv))


@lru_cache(maxsize=None)
def HasAttribute(obj, attr_str):
    for aid in range(obj.AttributesLength()):
        attr = obj.Attributes(aid)
        key = attr.Key().decode("utf-8")
        if key == attr_str:
            return True
    return False


@lru_cache(maxsize=None)
def IsSecure(obj):
    return HasAttribute(obj, _SECURE_ATTRIBUTE)


@lru_cache(maxsize=None)
def IsOptional(field):
    field_type = GetFieldType(field)
    if IsScalar(field_type.BaseType()):
        if field.Optional():
            return True
        raise Exception(
            "Scalar field %(name)s should must be optional"
            % {"name": field.Name().decode("utf-8")}
        )

    return HasAttribute(field, _OPTIONAL_ATTRIBUTE)


@lru_cache(maxsize=None)
def IsSerializable(schema, obj):
    if HasAttribute(obj, _SERIALIZABLE_ATTRIBUTE):
        return True

    if schema.RootTable() is None:
        return False

    return schema.RootTable().Name() == obj.Name()


@lru_cache(maxsize=None)
def IsScalar(base_type):
    return base_type in _SCALAR_SET


@lru_cache(maxsize=None)
def IsUType(data_type):
    if data_type.BaseType() == BaseType.UType:
        return True
    elif data_type.Element() == BaseType.UType:
        return True
    return False


@lru_cache(maxsize=None)
def IsUnion(data_type):
    if data_type.BaseType() == BaseType.Union:
        return True
    elif data_type.Element() == BaseType.Union:
        return True
    return False


# A workaround to make sure we always returning the same object.
# Returning unique objects from every accessor would mess up the caching of
# other function results.
@lru_cache(maxsize=None)
def GetObject(schema, idx):
    return schema.Objects(idx)


# A workaround to make sure we always returning the same enum object.
# Returning unique objects from every accessor would mess up the caching of
# other function results.
@lru_cache(maxsize=None)
def GetEnum(schema, idx):
    return schema.Enums(idx)


# A workaround to make sure we always returning the same values objects.
# Returning unique objects from every accessor would mess up the caching of
# other function results.
@lru_cache(maxsize=None)
def GetValues(enum):
    return tuple(enum.Values(vid) for vid in range(enum.ValuesLength()))


# A workaround to make sure we always returning the same field objects.
# Returning unique objects from every accessor would mess up the caching of
# other function results.
@lru_cache(maxsize=None)
def GetFields(obj):
    return tuple(obj.Fields(fid) for fid in range(obj.FieldsLength()))


@lru_cache(maxsize=None)
def GetSortedFields(obj):
    fields = list(GetFields(obj))
    fields.sort(key=lambda field: field.Id())
    return tuple(fields)


@lru_cache(maxsize=None)
def GetFieldType(field):
    return field.Type()


@lru_cache(maxsize=None)
def GetValueUnionType(value):
    return value.UnionType()


@lru_cache(maxsize=None)
def GetSimpleName(obj):
    return obj.Name().decode("utf-8").split(".")[-1]


@lru_cache(maxsize=None)
def GetNamespaces(obj, serialized_namespace=False):
    namespaces = obj.Name().decode("utf-8").split(".")[:-1]
    if not serialized_namespace:
        namespaces = namespaces[:-1]
    return tuple(namespaces)


@lru_cache(maxsize=None)
def IsNamespaceAllowed(obj, namespace_filter):
    # Allow everything if the namespace_filter is empty.
    if not namespace_filter:
        return True
    namespace = "::".join(GetNamespaces(obj))
    return namespace in namespace_filter


@lru_cache(maxsize=None)
def OutputNamespaceHead(target_namespace):
    template = Template(
        """
      namespace {{ target_namespace|join("::") }} {
    """
    )
    return template.render(target_namespace=target_namespace)


@lru_cache(maxsize=None)
def OutputNamespaceFoot(target_namespace):
    template = Template(
        """
      }  // namespace {{ target_namespace|join("::") }}
    """
    )
    return template.render(target_namespace=target_namespace)


@lru_cache(maxsize=None)
def OutputObjectType(obj, serialized=False):
    template = Template('::{{ full_name|join("::") }}')

    target_namespace = GetNamespaces(obj, serialized)

    full_name = list(target_namespace) + [GetSimpleName(obj)]
    return template.render(full_name=full_name)


@lru_cache(maxsize=None)
def OutputBaseType(base_type):
    if base_type in _BASE_TYPE_STRING:
        return _BASE_TYPE_STRING[base_type]
    raise Exception(
        "Unknown output for base type %(base_type)s"
        % {
            "base_type": base_type,
        }
    )


@lru_cache(maxsize=None)
def OutputType(schema, data_type, is_secure):
    base_type = data_type.BaseType()
    element_type = data_type.Element()
    if base_type == BaseType.None_:
        return "NONE"
    elif base_type == BaseType.Vector:
        if element_type == BaseType.Obj:
            inner_type = OutputObjectType(GetObject(schema, data_type.Index()))
        elif data_type.Index() != -1:
            inner_type = OutputObjectType(GetEnum(schema, data_type.Index()))
        elif element_type == BaseType.UByte:
            if is_secure:
                return "brillo::SecureBlob"
            else:
                return "brillo::Blob"
        else:
            inner_type = OutputBaseType(element_type)
        return _VECTOR_TEMPLATE.render(inner_type=inner_type)
    elif base_type == BaseType.Array:
        if element_type == BaseType.Obj:
            inner_type = OutputObjectType(GetObject(schema, data_type.Index()))
        elif data_type.Index() != -1:
            inner_type = OutputObjectType(GetEnum(schema, data_type.Index()))
        else:
            inner_type = OutputBaseType(element_type)
        return _ARRAY_TEMPLATE.render(
            inner_type=inner_type, size=data_type.FixedLength()
        )
    elif base_type == BaseType.Obj:
        return OutputObjectType(GetObject(schema, data_type.Index()))
    elif base_type == BaseType.Union:
        return OutputObjectType(GetEnum(schema, data_type.Index()))
    elif base_type == BaseType.UType:
        return OutputObjectType(GetEnum(schema, data_type.Index()))
    elif data_type.Index() != -1:  # Enum type.
        return OutputObjectType(GetEnum(schema, data_type.Index()))
    else:
        return OutputBaseType(base_type)


@lru_cache(maxsize=None)
def OutputFieldType(schema, field, is_secure):
    data_type = GetFieldType(field)
    is_optional = IsOptional(field)

    inner_type = OutputType(schema, data_type, is_secure)

    if is_optional:
        return _OPTIONAL_TEMPLATE.render(inner_type=inner_type)

    if data_type.BaseType() == BaseType.Union:
        return inner_type
    return inner_type


@lru_cache(maxsize=None)
def OutputStructure(schema, obj):
    template = Template(
        """
        {{ namespace_head }}
        struct {{ simple_name }} {
          {% if blob_type is not none %}
            {{optional_type}}<{{ blob_type }}> Serialize() const;
            static {{optional_type}}<{{ simple_name }}> Deserialize(const {{ blob_type }}&);
          {% endif %}

          {% for (field_type, field_name) in fields %} \
            {{ field_type }} {{ field_name }}; \
          {% endfor %}
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(obj)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    is_secure = IsSecure(obj)
    is_serializable = IsSerializable(schema, obj)

    simple_name = GetSimpleName(obj)

    blob_type = None
    if is_serializable:
        if is_secure:
            blob_type = "brillo::SecureBlob"
        else:
            blob_type = "brillo::Blob"

    fields = []
    for field in GetSortedFields(obj):
        if IsUType(GetFieldType(field)):
            continue
        field_name = field.Name().decode("utf-8")
        field_type = OutputFieldType(schema, field, is_secure)
        fields.append((field_type, field_name))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        optional_type=_CPP_OPTIONAL_TYPE,
        blob_type=blob_type,
        simple_name=simple_name,
        fields=fields,
    )


@lru_cache(maxsize=None)
def OutputVariant(schema, union):
    template = Template(
        """
        {{ namespace_head }}
        using {{ simple_name }} = {{ variant_type }}<
          {{ types | join(",") }}
          >;
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(union)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    simple_name = GetSimpleName(union)

    types = [_CPP_MONOSTATE_TYPE]

    for value in GetValues(union):
        union_type = GetValueUnionType(value)
        if union_type.BaseType() != BaseType.None_:
            types.append(OutputType(schema, union_type, False))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        simple_name=simple_name,
        variant_type=_CPP_VARIANT_TYPE,
        types=types,
    )


@lru_cache(maxsize=None)
def OutputEnum(enum):
    template = Template(
        """
        {{ namespace_head }}
        enum class {{ simple_name }} : {{ underlying_type }} {
          {% for (field, value) in fields %} \
            {{ field }} = {{ value }}, \
          {% endfor %}
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(enum)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    simple_name = GetSimpleName(enum)
    underlying_type = OutputBaseType(enum.UnderlyingType().BaseType())

    fields = []

    for value in GetValues(enum):
        fields.append((value.Name().decode("utf-8"), str(value.Value())))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        simple_name=simple_name,
        underlying_type=underlying_type,
        fields=fields,
    )


@lru_cache(maxsize=None)
def OutputEnumToFlatBuffer(enum):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct ToFlatBuffer<{{ enum_type }}> {
          using ResultType = {{ serialized_type }};

          ResultType operator()(flatbuffers::FlatBufferBuilder* builder,
                                 {{ enum_type }} object) const {
            return static_cast<ResultType>(object);
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(enum, True)
    enum_type = OutputObjectType(enum, False)
    simple_name = GetSimpleName(enum)

    fields = []

    for value in GetValues(enum):
        fields.append(value.Name().decode("utf-8"))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        enum_type=enum_type,
        serialized_type=serialized_type,
        simple_name=simple_name,
        fields=fields,
    )


@lru_cache(maxsize=None)
def OutputUnionTypeToFlatBuffer(schema, union):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct ToFlatBuffer<{{ union_type }}, IsUnionEnum> {
          using ResultType = {{ serialized_type }};

          ResultType operator()(flatbuffers::FlatBufferBuilder* builder,
                                 const {{ union_type }}& object) const {
            return {{ visit }}(
              [](const auto& arg) -> {{ serialized_type }} {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, {{ monostate_type }}>)
                  return {{ serialized_type }}::NONE;
                {% for (value_type, value_name) in values %} \
                  else if constexpr (std::is_same_v<T, {{ value_type }}>)
                    return {{ serialized_type }}::{{ value_name }}; \
                {% endfor %}
            }, object);
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(union, True)
    union_type = OutputObjectType(union, False)
    simple_name = GetSimpleName(union)

    values = []
    for value in GetValues(union):
        value_union_type = GetValueUnionType(value)
        if value_union_type.BaseType() == BaseType.None_:
            continue
        value_type = OutputType(schema, value_union_type, False)
        value_name = value.Name().decode("utf-8")
        values.append((value_type, value_name))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        serialized_type=serialized_type,
        union_type=union_type,
        simple_name=simple_name,
        values=values,
        visit=_CPP_VISIT,
        monostate_type=_CPP_MONOSTATE_TYPE,
    )


@lru_cache(maxsize=None)
def OutputStructureToFlatBuffer(schema, obj):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct ToFlatBuffer<{{ obj_type }}>{
          using ResultType = flatbuffers::Offset<{{ serialized_type }}>;

          ResultType operator()(flatbuffers::FlatBufferBuilder* builder,
                                 const {{ obj_type }} & object) const {
            {% for (field_name, real_name, field_type) in field_data %} \
              auto {{ field_name }} = ToFlatBuffer<{{ field_type }}>()(builder, object.{{ real_name }});
            {% endfor %}
            return {{ create_func_name }}(*builder
              {% for (field_name, real_name, field_type) in field_data %} \
                , {{ field_name }} \
              {% endfor %}
            );
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(obj, True)
    obj_type = OutputObjectType(obj, False)
    simple_name = GetSimpleName(obj)

    split_serial = serialized_type.split("::")
    split_serial[-1] = "Create" + split_serial[-1]
    create_func_name = "::".join(split_serial)

    is_secure = IsSecure(obj)

    field_data = []
    for field in GetSortedFields(obj):
        name = field.Name().decode("utf-8")
        field_type = GetFieldType(field)
        inner_type = OutputFieldType(schema, field, is_secure)

        if IsUType(field_type):
            inner_type += ", IsUnionEnum"
            # TODO(yich): switch to removesuffix() once we update to Python 3.9.
            real_name = re.sub("_type$", "", name)
        else:
            real_name = name

        field_data.append((name, real_name, inner_type))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        simple_name=simple_name,
        obj_type=obj_type,
        serialized_type=serialized_type,
        field_data=field_data,
        create_func_name=create_func_name,
    )


@lru_cache(maxsize=None)
def OutputStructureSerializer(obj):
    template = Template(
        """
        {{ namespace_head }}
        {{ export_attribute }}
        {{ result_type }} {{ simple_name }}::Serialize() const {
          {% if is_secure %} \
            {{ converter|join("::") }}::FlatbufferSecureAllocatorBridge
                allocator;
            flatbuffers::FlatBufferBuilder builder(
                kFlatbufferAllocatorInitialSize, &allocator); \
          {% else %} \
            flatbuffers::FlatBufferBuilder builder; \
          {% endif%}
          auto buffer = {{ converter|join("::") }}::ToFlatBuffer<
                    {{ obj_type }}>()(&builder, *this);
          if (buffer.IsNull()) {
            LOG(ERROR) << "{{ simple_name }} cannot be serialized.";
            return {{ nullopt }};
          }
          builder.Finish(buffer);
          uint8_t* buf = builder.GetBufferPointer();
          int size = builder.GetSize();
          {% if is_secure %} \
            return brillo::SecureBlob(buf, buf + size);
          {% else %} \
            return brillo::Blob(buf, buf + size);
          {% endif%}
        }
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(obj)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    is_secure = IsSecure(obj)

    if is_secure:
        blob_type = "brillo::SecureBlob"
    else:
        blob_type = "brillo::Blob"

    result_type = _OPTIONAL_TEMPLATE.render(inner_type=blob_type)
    obj_type = OutputObjectType(obj)
    simple_name = GetSimpleName(obj)

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        export_attribute=_EXPORT_ATTRIBUTE,
        converter=_CONVERTER_NAMESPACE,
        result_type=result_type,
        is_secure=is_secure,
        obj_type=obj_type,
        simple_name=simple_name,
        nullopt=_CPP_NULLOPT,
    )


@lru_cache(maxsize=None)
def OutputEnumFromFlatBuffer(enum):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct FromFlatBuffer<{{ enum_type }}> {
          {{ result_type }} operator()({{ serialized_type }} object) const {
            return static_cast<{{ result_type }}>(object);
          }

          {{ result_type }} operator()(
                std::underlying_type_t<{{ serialized_type }}> object) const {
            return static_cast<{{ result_type }}>(object);
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(enum, True)
    enum_type = OutputObjectType(enum, False)
    simple_name = GetSimpleName(enum)

    result_type = enum_type

    fields = []
    for value in GetValues(enum):
        fields.append(value.Name().decode("utf-8"))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        result_type=result_type,
        enum_type=enum_type,
        serialized_type=serialized_type,
        simple_name=simple_name,
        fields=fields,
    )


@lru_cache(maxsize=None)
def OutputUnionFromFlatBuffer(schema, union):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct FromFlatBuffer<{{ union_type }}> {
          {{ result_type }} operator()(const void* object, {{ serialized_type }} type) const {
            if (object == nullptr) {
              return {{ monostate_type }}();
            }
            switch (type) {
              case {{ serialized_type }}::NONE: {
                return {{ monostate_type }}();
              }
              {% for (field_name, obj_type, serial_obj_type) in field_data %} \
                case {{ serialized_type }}::{{ field_name }}: {
                  return FromFlatBuffer<{{ obj_type }}>()(static_cast<const {{ serial_obj_type }}*>(object));
                }
              {% endfor %}
            }
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(union, True)
    union_type = OutputObjectType(union, False)
    simple_name = GetSimpleName(union)
    result_type = union_type

    field_data = []
    for value in GetValues(union):
        value_union_type = GetValueUnionType(value)
        if value_union_type.BaseType() == BaseType.None_:
            continue

        field_name = value.Name().decode("utf-8")
        obj = GetObject(schema, value_union_type.Index())
        obj_type = OutputObjectType(obj, False)
        serial_obj_type = OutputObjectType(obj, True)
        field_data.append((field_name, obj_type, serial_obj_type))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        union_type=union_type,
        result_type=result_type,
        serialized_type=serialized_type,
        simple_name=simple_name,
        field_data=field_data,
        monostate_type=_CPP_MONOSTATE_TYPE,
    )


@lru_cache(maxsize=None)
def OutputStructureFromFlatBuffer(schema, obj):
    template = Template(
        """
        {{ namespace_head }}
        template <>
        struct FromFlatBuffer<{{ obj_type }}> {
          {{ result_type }} operator()(const {{ serialized_type }}* object) const {
            if (object == nullptr) {
              return {{ result_type }}();
            }
            return {{ obj_type }}{
              {% for (field_name, field_type, field_input) in field_data %} \
                .{{ field_name }} = FromFlatBuffer<{{ field_type }}>()({{ field_input }}), \
              {% endfor %}
            };
          }
        };
        {{ namespace_foot }}
    """
    )

    target_namespace = _CONVERTER_NAMESPACE
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    serialized_type = OutputObjectType(obj, True)
    obj_type = OutputObjectType(obj, False)
    result_type = obj_type
    simple_name = GetSimpleName(obj)

    is_secure = IsSecure(obj)

    field_data = []

    for field in GetSortedFields(obj):
        field_name = field.Name().decode("utf-8")
        field_type = GetFieldType(field)

        if IsUType(field_type):
            continue

        inner_type = OutputFieldType(schema, field, is_secure)

        field_input = "object->%(field_name)s()" % {"field_name": field_name}

        if IsUnion(field_type):
            field_input += ", object->%(field_name)s_type()" % {
                "field_name": field_name
            }

        field_data.append((field_name, inner_type, field_input))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        obj_type=obj_type,
        serialized_type=serialized_type,
        result_type=result_type,
        simple_name=simple_name,
        field_data=field_data,
    )


@lru_cache(maxsize=None)
def OutputStructureDeserializer(obj):
    template = Template(
        """
        {{ namespace_head }}
        // static
        {{ export_attribute }}
        {{ result_type }} {{ simple_name }}::Deserialize(const {{ blob_type }}& blob) {
          flatbuffers::Verifier verifier(blob.data(), blob.size());
          if (!{{ serial_verify }}(verifier)) {
            LOG(ERROR) << "{{ simple_name }} cannot be deserialized.";
            return {{ nullopt }};
          }

          const {{ serialized_type }}* object = flatbuffers::GetRoot<{{ serialized_type }}>(blob.data());

          return {{ converter|join("::") }}::FromFlatBuffer<{{ obj_type }}>()(object);
        }
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(obj)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    is_secure = IsSecure(obj)

    simple_name = GetSimpleName(obj)

    serialized_type = OutputObjectType(obj, True)
    obj_type = OutputObjectType(obj, False)

    if is_secure:
        blob_type = "brillo::SecureBlob"
    else:
        blob_type = "brillo::Blob"

    result_type = _OPTIONAL_TEMPLATE.render(inner_type=obj_type)

    split_serial = serialized_type.split("::")
    split_serial[-1] = "Verify" + split_serial[-1] + "Buffer"
    serial_verify = "::".join(split_serial)

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        export_attribute=_EXPORT_ATTRIBUTE,
        converter=_CONVERTER_NAMESPACE,
        result_type=result_type,
        obj_type=obj_type,
        serialized_type=serialized_type,
        blob_type=blob_type,
        serial_verify=serial_verify,
        simple_name=simple_name,
        nullopt=_CPP_NULLOPT,
    )


@lru_cache(maxsize=None)
def OutputTestStructure(obj):
    template = Template(
        """
        {{ namespace_head }}
        inline bool operator==(const {{ name }}& lhs, const {{ name }}& rhs) {
          return true \
          {% for field in fields %} \
            && lhs.{{ field }} == rhs.{{ field }} \
          {% endfor %} \
          ;
        }
        inline bool operator!=(const {{ name }}& lhs, const {{ name }}& rhs) {
          return !(lhs == rhs);
        }
        {{ namespace_foot }}
    """
    )

    target_namespace = GetNamespaces(obj)
    namespace_head = OutputNamespaceHead(target_namespace)
    namespace_foot = OutputNamespaceFoot(target_namespace)

    name = GetSimpleName(obj)

    fields = []
    for field in GetSortedFields(obj):
        if not IsUType(GetFieldType(field)):
            fields.append(field.Name().decode("utf-8"))

    return template.render(
        namespace_head=namespace_head,
        namespace_foot=namespace_foot,
        name=name,
        fields=fields,
    )


@lru_cache(maxsize=None)
def TypeToID(data_type):
    base_type = data_type.BaseType()
    element_type = data_type.Element()
    if base_type == BaseType.Vector:
        if element_type == BaseType.Obj:
            return (_OBJECT_TOPOSORT_TYPE, data_type.Index())
        elif data_type.Index() != -1:
            return (_ENUM_TOPOSORT_TYPE, data_type.Index())
        else:
            return None
    elif base_type == BaseType.Array:
        if element_type == BaseType.Obj:
            return (_OBJECT_TOPOSORT_TYPE, data_type.Index())
        elif data_type.Index() != -1:
            return (_ENUM_TOPOSORT_TYPE, data_type.Index())
        else:
            return None
    elif base_type == BaseType.Obj:
        return (_OBJECT_TOPOSORT_TYPE, data_type.Index())
    elif data_type.Index() != -1:
        return (_ENUM_TOPOSORT_TYPE, data_type.Index())
    return None


@lru_cache(maxsize=None)
def CheckSecure(schema, node_id):
    node_type, entity_id = node_id

    inner_ids = []

    if node_type == _ENUM_TOPOSORT_TYPE:
        enum = GetEnum(schema, entity_id)
        is_secure = IsSecure(enum)
        name = enum.Name().decode("utf-8")
        for value in GetValues(enum):
            inner_id = TypeToID(GetValueUnionType(value))
            if inner_id is not None:
                inner_ids.append(inner_id)

    elif node_type == _OBJECT_TOPOSORT_TYPE:
        obj = GetObject(schema, entity_id)
        is_secure = IsSecure(obj)
        name = obj.Name().decode("utf-8")
        for field in GetFields(obj):
            inner_id = TypeToID(GetFieldType(field))
            if inner_id is not None:
                inner_ids.append(inner_id)

    for inner_id in inner_ids:
        inner_secure = CheckSecure(schema, inner_id)
        if not is_secure and inner_secure:
            raise Exception(
                "%(name)s must have secure attribute"
                % {
                    "name": name,
                }
            )

        # TODO(yich): Ensure we don't put insecure table inside secure table.
        if is_secure and not inner_secure:
            logging.warning("Not all internal data of %s is secure", name)

    return is_secure


# Check every object is inside the serialized namespace.
# So the developers would not confused about why the last namespace disappeared
# if they forget to add the serialized namespace.
@lru_cache(maxsize=None)
def CheckSerializedNamespaces(obj):
    namespaces = obj.Name().decode("utf-8").split(".")[:-1]
    if namespaces[-1] != _SERIALIZED_NAMESPACE:
        raise Exception(
            "The last namespace of %(obj)s must be %(serialized_namespace)s"
            % {
                "obj": obj.Name().decode("utf-8"),
                "serialized_namespace": _SERIALIZED_NAMESPACE,
            }
        )


@lru_cache(maxsize=None)
def SchemaCheck(schema):
    for object_id in range(schema.ObjectsLength()):
        obj = GetObject(schema, object_id)
        CheckSerializedNamespaces(obj)
        CheckSecure(schema, (_OBJECT_TOPOSORT_TYPE, object_id))


@lru_cache(maxsize=None)
def TopologicalSort(schema):
    topo_order = []
    visited = set()

    def dfs(node_id):
        if node_id is None:
            return
        if node_id in visited:
            return
        visited.add(node_id)

        node_type, entity_id = node_id

        if node_type == _ENUM_TOPOSORT_TYPE:
            enum = GetEnum(schema, entity_id)
            for value in GetValues(enum):
                dfs(TypeToID(GetValueUnionType(value)))
        elif node_type == _OBJECT_TOPOSORT_TYPE:
            obj = GetObject(schema, entity_id)
            for field in GetFields(obj):
                dfs(TypeToID(GetFieldType(field)))
        topo_order.append(node_id)

    for enum_id in range(schema.EnumsLength()):
        dfs((_ENUM_TOPOSORT_TYPE, enum_id))

    for object_id in range(schema.ObjectsLength()):
        dfs((_OBJECT_TOPOSORT_TYPE, object_id))

    return topo_order


@lru_cache(maxsize=None)
def ClangFormatCode(code):
    format_out = run(
        [
            "clang-format",
            "-style={"
            'BasedOnStyle: "Chromium", '
            "AllowAllParametersOfDeclarationOnNextLine: true}",
        ],
        stdout=PIPE,
        input=code,
        encoding="ascii",
        check=True,
    )
    return format_out.stdout


@lru_cache(maxsize=None)
def OutputBindingHeader(schema, guard_name, include_paths, namespace_filter):
    template = Template(
        """\
        {{ copyright }}

        #ifndef {{ guard_name }}
        #define {{ guard_name }}

        #include <optional>
        #include <stdint.h>
        #include <string>
        #include <variant>
        #include <vector>

        #include <brillo/secure_blob.h>

        {% for include_path in include_paths %} \
            #include "{{ include_path }}"
        {% endfor %}

        {% for definition in definitions %}
            {{ definition }}
        {% endfor %}

        #endif  // {{ guard_name }}
    """
    )

    order = TopologicalSort(schema)

    definitions = []
    for node_id in order:
        node_type, entity_id = node_id
        if node_type == _OBJECT_TOPOSORT_TYPE:
            obj = GetObject(schema, entity_id)
            if not IsNamespaceAllowed(obj, namespace_filter):
                continue
            definitions.append(OutputStructure(schema, obj))
        elif node_type == _ENUM_TOPOSORT_TYPE:
            enum = GetEnum(schema, entity_id)
            if not IsNamespaceAllowed(enum, namespace_filter):
                continue
            if enum.IsUnion():
                definitions.append(OutputVariant(schema, enum))
            else:
                definitions.append(OutputEnum(enum))

    header = template.render(
        copyright=_COPYRIGHT_HEADER,
        guard_name=guard_name,
        include_paths=include_paths,
        definitions=definitions,
    )

    return ClangFormatCode(header)


@lru_cache(maxsize=None)
def OutputBindingFlatbufferHeader(
    schema, guard_name, include_paths, namespace_filter
):
    template = Template(
        """\
        {{ copyright }}

        #ifndef {{ guard_name }}
        #define {{ guard_name }}

        #include <optional>
        #include <stdint.h>
        #include <string>
        #include <type_traits>
        #include <variant>
        #include <vector>

        #include <brillo/secure_blob.h>
        #include <flatbuffers/flatbuffers.h>

        {% for include_path in include_paths %} \
            #include "{{ include_path }}"
        {% endfor %}

        {% for implementation in implementations %}
            {{ implementation }}
        {% endfor %}

        #endif  // {{ guard_name }}
    """
    )

    order = TopologicalSort(schema)

    implementations = []
    for node_id in order:
        node_type, entity_id = node_id
        if node_type == _OBJECT_TOPOSORT_TYPE:
            obj = GetObject(schema, entity_id)
            if not IsNamespaceAllowed(obj, namespace_filter):
                continue
            implementations.append(OutputStructureToFlatBuffer(schema, obj))
            implementations.append(OutputStructureFromFlatBuffer(schema, obj))
        elif node_type == _ENUM_TOPOSORT_TYPE:
            enum = GetEnum(schema, entity_id)
            if not IsNamespaceAllowed(enum, namespace_filter):
                continue
            if enum.IsUnion():
                implementations.append(
                    OutputUnionTypeToFlatBuffer(schema, enum)
                )
                implementations.append(OutputUnionFromFlatBuffer(schema, enum))
            else:
                implementations.append(OutputEnumToFlatBuffer(enum))
                implementations.append(OutputEnumFromFlatBuffer(enum))

    header = template.render(
        copyright=_COPYRIGHT_HEADER,
        guard_name=guard_name,
        include_paths=include_paths,
        implementations=implementations,
    )

    return ClangFormatCode(header)


@lru_cache(maxsize=None)
def OutputBindingImpl(schema, include_paths, namespace_filter):
    template = Template(
        """\
        {{ copyright }}

        #include <optional>
        #include <stdint.h>
        #include <string>
        #include <variant>
        #include <vector>

        #include <base/logging.h>
        #include <brillo/secure_blob.h>
        #include <flatbuffers/flatbuffers.h>

        {% for include_path in include_paths %} \
            #include "{{ include_path }}"
        {% endfor %}

        namespace {
        [[maybe_unused]] constexpr int kFlatbufferAllocatorInitialSize = 4096;
        } //  namespaces

        {% for implementation in implementations %}
            {{ implementation }}
        {% endfor %}
    """
    )

    order = TopologicalSort(schema)

    implementations = []

    for node_id in order:
        node_type, entity_id = node_id
        if node_type == _OBJECT_TOPOSORT_TYPE:
            obj = GetObject(schema, entity_id)
            if not IsNamespaceAllowed(obj, namespace_filter):
                continue
            if IsSerializable(schema, obj):
                implementations.append(OutputStructureSerializer(obj))
                implementations.append(OutputStructureDeserializer(obj))

    impl = template.render(
        copyright=_COPYRIGHT_HEADER,
        include_paths=include_paths,
        implementations=implementations,
    )

    return ClangFormatCode(impl)


@lru_cache(maxsize=None)
def OutputBindingTestUtilsHeader(
    schema, guard_name, include_paths, namespace_filter
):
    template = Template(
        """\
        {{ copyright }}

        #ifndef {{ guard_name }}
        #define {{ guard_name }}

        {% for include_path in include_paths %} \
            #include "{{ include_path }}"
        {% endfor %}

        {% for implementation in implementations %}
            {{ implementation }}
        {% endfor %}

        #endif  // {{ guard_name }}
    """
    )

    order = TopologicalSort(schema)

    implementations = []
    for node_id in order:
        node_type, entity_id = node_id
        if node_type == _OBJECT_TOPOSORT_TYPE:
            obj = GetObject(schema, entity_id)
            if not IsNamespaceAllowed(obj, namespace_filter):
                continue
            implementations.append(OutputTestStructure(obj))

    header = template.render(
        copyright=_COPYRIGHT_HEADER,
        guard_name=guard_name,
        include_paths=include_paths,
        implementations=implementations,
    )

    return ClangFormatCode(header)


def main():
    parser = argparse.ArgumentParser(
        description="flatbuffers c++ binding code generator"
    )
    parser.add_argument(
        "--output_dir", default=".", help="The output directory"
    )
    parser.add_argument(
        "--guard_prefix", default="FLATBUFFER_BINDING", help="The guard prefix"
    )
    parser.add_argument(
        "--header_include_paths",
        default=[],
        help="The include path for header",
        action="append",
    )
    parser.add_argument(
        "--flatbuffer_header_include_paths",
        default=[],
        help="The include path for flatbuffer utils header",
        action="append",
    )
    parser.add_argument(
        "--impl_include_paths",
        default=[],
        help="The include path for implementation",
        action="append",
    )
    parser.add_argument(
        "--test_utils_header_include_paths",
        default=[],
        help="The include path for testing utils header",
        action="append",
    )
    parser.add_argument(
        "--filter_by_namespace",
        default=[],
        help="Output the objects that match filter namespace",
        action="append",
    )
    parser.add_argument("input_files", nargs="*")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    for input_path in args.input_files:
        with open(input_path, mode="rb") as input_file:
            buf = input_file.read()
            schema = Schema.GetRootAs(buf, 0)

        base_name = os.path.splitext(os.path.basename(input_path))[0]

        header_file_path = os.path.join(args.output_dir, base_name + ".h")
        header_flatbuffer_file_path = os.path.join(
            args.output_dir, base_name + "_flatbuffer.h"
        )
        impl_file_path = os.path.join(args.output_dir, base_name + ".cc")
        test_utils_header_file_path = os.path.join(
            args.output_dir, base_name + "_test_utils.h"
        )

        base_guard = "%(prefix)s_%(base)s_" % {
            "prefix": args.guard_prefix.upper(),
            "base": base_name.upper(),
        }

        guard_name = base_guard + "H_"
        header_flatbuffer_guard_name = base_guard + "FLATBUFFER_H_"
        test_utils_guard_name = base_guard + "TEST_UTILS_H_"

        SchemaCheck(schema)

        with open(header_file_path, "w") as output_file:
            output_file.write(
                OutputBindingHeader(
                    schema,
                    guard_name,
                    tuple(args.header_include_paths),
                    tuple(args.filter_by_namespace),
                )
            )

        with open(header_flatbuffer_file_path, "w") as output_file:
            output_file.write(
                OutputBindingFlatbufferHeader(
                    schema,
                    header_flatbuffer_guard_name,
                    tuple(args.flatbuffer_header_include_paths),
                    tuple(args.filter_by_namespace),
                )
            )

        with open(impl_file_path, "w") as output_file:
            output_file.write(
                OutputBindingImpl(
                    schema,
                    tuple(args.impl_include_paths),
                    tuple(args.filter_by_namespace),
                )
            )

        with open(test_utils_header_file_path, "w") as output_file:
            output_file.write(
                OutputBindingTestUtilsHeader(
                    schema,
                    test_utils_guard_name,
                    tuple(args.test_utils_header_include_paths),
                    tuple(args.filter_by_namespace),
                )
            )


if __name__ == "__main__":
    main()
