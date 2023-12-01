// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package dbustype provides utility functions for generators to parse a D-Bus type
// (protobuf types, which chromeos-dbus-binding additionally supports, is not included) and
// generate the corresponding C++ type.
package dbustype

import (
	"fmt"
	"strings"
)

// dbusKind is an enum to represent a kind of a D-Bus type.
type dbusKind int

const (
	dbusKindBoolean dbusKind = iota + 1
	dbusKindByte
	dbusKindDouble
	dbusKindInt16
	dbusKindInt32
	dbusKindInt64
	dbusKindUint16
	dbusKindUint32
	dbusKindUint64
	dbusKindObjectPath
	dbusKindString
	dbusKindVariant
	dbusKindFileDescriptor
	dbusKindVariantDict
	dbusKindDict
	dbusKindArray
	dbusKindStruct
)

// dbusType represents a D-Bus type.
type dbusType struct {
	kind dbusKind
	// If kind is dbusKindArray, the length of args must be 1.
	// If kind is dbusKindVariantDict, the length of args must be 2.
	args []dbusType
}

// BaseType returns the C++ type corresponding to the D-Bus type.
func (d *dbusType) BaseType() string {
	switch d.kind {
	case dbusKindBoolean:
		return "bool"
	case dbusKindByte:
		return "uint8_t"
	case dbusKindDouble:
		return "double"
	case dbusKindInt16:
		return "int16_t"
	case dbusKindInt32:
		return "int32_t"
	case dbusKindInt64:
		return "int64_t"
	case dbusKindUint16:
		return "uint16_t"
	case dbusKindUint32:
		return "uint32_t"
	case dbusKindUint64:
		return "uint64_t"
	case dbusKindObjectPath:
		return "dbus::ObjectPath"
	case dbusKindString:
		return "std::string"
	case dbusKindVariant:
		return "brillo::Any"
	case dbusKindVariantDict:
		return "brillo::VariantDictionary"
	case dbusKindFileDescriptor:
		return "base::ScopedFD"
	case dbusKindArray:
		return fmt.Sprintf("std::vector<%s>", d.args[0].BaseType())
	case dbusKindDict:
		return fmt.Sprintf("std::map<%s, %s>", d.args[0].BaseType(), d.args[1].BaseType())
	case dbusKindStruct:
		var mems []string
		for _, arg := range d.args {
			mems = append(mems, arg.BaseType())
		}
		return fmt.Sprintf("std::tuple<%s>", strings.Join(mems, ", "))
	}

	return ""
}

var scalars = []dbusKind{
	dbusKindBoolean,
	dbusKindByte,
	dbusKindDouble,
	dbusKindInt16,
	dbusKindInt32,
	dbusKindInt64,
	dbusKindUint16,
	dbusKindUint32,
	dbusKindUint64,
}

// scalar tells whether d is a scalar type.
func (d *dbusType) scalar() bool {
	for _, s := range scalars {
		if d.kind == s {
			return true
		}
	}
	return false
}

// InArgType returns the C++ type corresponding to the D-Bus type for an in argument.
func (d *dbusType) InArgType() string {
	baseType := d.BaseType()

	if d.scalar() {
		return baseType
	}
	return fmt.Sprintf("const %s&", baseType)
}

// OutArgType returns the C++ type corresponding to the D-Bus type for an out argument.
func (d *dbusType) OutArgType() string {
	return fmt.Sprintf("%s*", d.BaseType())
}

// TODO(chromium:983008): define ValidPropertyType and CallbackArgType func.
