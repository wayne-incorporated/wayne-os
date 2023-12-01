// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dbustype

import (
	"errors"
	"fmt"
)

// Parse returns a DBusType corresponding to the signature |s|.
// |s| needs to be a signature made up of a single complete type.
// Note that this function does not support an extension about protobuf defined as an annotation
// of a MethodArg and a SignalArg. Consider using BaseType, InArgType or OutArgType defined in
// introspect package in order to take C++ types of those Args.
func Parse(s string) (dbusType, error) {
	typs, err := parseSignature(s, 0)
	if err != nil {
		return dbusType{}, err
	}
	if len(typs) != 1 {
		return dbusType{}, fmt.Errorf("%s is not a signature made up of a single complete type", s)
	}
	return typs[0], nil
}

// In D-Bus specification, the maximum length of signature is 255.
const maxSignatureLength = 255

// parseSignature returns a slice of DBusType corresponding to the signature |s|.
// Incidentally, in D-Bus specification, signature is made up of zero or more single complete types.
func parseSignature(s string, index int) ([]dbusType, error) {
	if len(s) > maxSignatureLength {
		return nil, fmt.Errorf("the length of signature exceeds the maximum value, signature is %q", s)
	}

	var ret []dbusType
	for index < len(s) {
		t, i, err := parseCompleteType(s, index, 0, 0)
		if err != nil {
			return nil, fmt.Errorf("parseCompleteType(%q, %d, 0, 0) faild: %v", s, index, err)
		}
		ret = append(ret, t)
		index = i
	}
	return ret, nil
}

// In D-Bus specification, the maximum depth of array and struct type nesting is 32 for each.
const maxArrayDepth = 32
const maxStructDepth = 32

// parseCompleteType parses a single complete type which is a substring of the signature |s|
// beginning from |index|, and returns a DBusType corresponding to the single complete type.
// This function also returns the next index to see.
func parseCompleteType(s string, index int, arrayDepth int, structDepth int) (dbusType, int, error) {
	if index >= len(s) {
		return dbusType{}, 0, fmt.Errorf("more type codes to follow %q are needed", s)
	}

	switch s[index] {
	case 'b':
		return dbusType{kind: dbusKindBoolean}, index + 1, nil
	case 'y':
		return dbusType{kind: dbusKindByte}, index + 1, nil
	case 'd':
		return dbusType{kind: dbusKindDouble}, index + 1, nil
	case 'o':
		return dbusType{kind: dbusKindObjectPath}, index + 1, nil
	case 'n':
		return dbusType{kind: dbusKindInt16}, index + 1, nil
	case 'i':
		return dbusType{kind: dbusKindInt32}, index + 1, nil
	case 'x':
		return dbusType{kind: dbusKindInt64}, index + 1, nil
	case 's':
		return dbusType{kind: dbusKindString}, index + 1, nil
	case 'h':
		return dbusType{kind: dbusKindFileDescriptor}, index + 1, nil
	case 'q':
		return dbusType{kind: dbusKindUint16}, index + 1, nil
	case 'u':
		return dbusType{kind: dbusKindUint32}, index + 1, nil
	case 't':
		return dbusType{kind: dbusKindUint64}, index + 1, nil
	case 'v':
		return dbusType{kind: dbusKindVariant}, index + 1, nil
	case 'a':
		index++

		arrayDepth++
		if arrayDepth > maxArrayDepth {
			return dbusType{}, 0, errors.New("excessive nesting depth of array")
		}

		if index >= len(s) {
			return dbusType{}, 0, fmt.Errorf("at end of string while reading array parameter")
		}

		if s[index] != '{' { // array case
			t, i, err := parseCompleteType(s, index, arrayDepth, structDepth)
			if err != nil {
				return dbusType{}, 0, err
			}
			return dbusType{kind: dbusKindArray, args: []dbusType{t}}, i, nil
		}

		// dictionary case

		// Check for VariantDictionary, which is a special case.
		if index+3 < len(s) && s[index:index+4] == "{sv}" {
			return dbusType{kind: dbusKindVariantDict}, index + 4, nil
		}

		index++
		var args []dbusType
		for index < len(s) {
			if s[index] == '}' {
				if len(args) == 2 {
					return dbusType{kind: dbusKindDict, args: args}, index + 1, nil
				}
				return dbusType{}, 0, errors.New("dict entries must have 2 sub-types")
			}

			t, i, err := parseCompleteType(s, index, arrayDepth, structDepth)
			if err != nil {
				return dbusType{}, 0, err
			}
			args = append(args, t)
			index = i
		}
		return dbusType{}, 0, errors.New("unmatched '{'")
	case '(': // struct case
		index++

		structDepth++
		if structDepth > maxStructDepth {
			return dbusType{}, 0, errors.New("excessive nesting depth of struct")
		}

		var args []dbusType
		for index < len(s) {
			if s[index] == ')' {
				return dbusType{kind: dbusKindStruct, args: args}, index + 1, nil
			}

			t, i, err := parseCompleteType(s, index, arrayDepth, structDepth)
			if err != nil {
				return dbusType{}, 0, err
			}
			args = append(args, t)
			index = i
		}
		return dbusType{}, 0, errors.New("unmatched '('")
	default:
		return dbusType{}, 0, fmt.Errorf("unexpected type code: %c (index: %d)", s[index], index)
	}
}
