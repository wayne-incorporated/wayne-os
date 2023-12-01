// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package dbustype_test

import (
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/dbustype"

	"github.com/google/go-cmp/cmp"
)

func TestParseFailures(t *testing.T) {
	cases := []string{
		"a{sv}Garbage", "", "a", "a{}", "a{s}", "a{sa}i", "a{s", "al", "(l)", "(i",
		"^MyProtobufClass", "a{s{i}}", "a{sa{i}u}", "a{a{u}", "a}i{",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai",
		"(((((((((((((((((((((((((((((((((i)))))))))))))))))))))))))))))))))",
	}
	for _, tc := range cases {
		if _, err := dbustype.Parse(tc); err == nil {
			t.Errorf("Expected signature %s to fail but it succeeded", tc)
		}
	}
}

func TestParseSuccesses(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Simple types.
		{"b", "bool"},
		{"y", "uint8_t"},
		{"d", "double"},
		{"o", "dbus::ObjectPath"},
		{"n", "int16_t"},
		{"i", "int32_t"},
		{"x", "int64_t"},
		{"s", "std::string"},
		{"q", "uint16_t"},
		{"u", "uint32_t"},
		{"t", "uint64_t"},
		{"h", "base::ScopedFD"},
		{"v", "brillo::Any"},

		// Complex types.
		{"ab", "std::vector<bool>"},
		{"ay", "std::vector<uint8_t>"},
		{"aay", "std::vector<std::vector<uint8_t>>"},
		{"ao", "std::vector<dbus::ObjectPath>"},
		{"ah", "std::vector<base::ScopedFD>"},
		{"a{oa{sa{sv}}}",
			"std::map<dbus::ObjectPath, std::map<std::string, brillo::VariantDictionary>>"},
		{"a{os}", "std::map<dbus::ObjectPath, std::string>"},
		{"a{ih}", "std::map<int32_t, base::ScopedFD>"},
		{"as", "std::vector<std::string>"},
		{"a{ss}", "std::map<std::string, std::string>"},
		{"a{sa{ss}}",
			"std::map<std::string, std::map<std::string, std::string>>"},
		{"a{sa{sv}}", "std::map<std::string, brillo::VariantDictionary>"},
		{"a{sv}", "brillo::VariantDictionary"},
		{"at", "std::vector<uint64_t>"},
		{"a{iv}", "std::map<int32_t, brillo::Any>"},
		{"(ib)", "std::tuple<int32_t, bool>"},
		{"(ih)", "std::tuple<int32_t, base::ScopedFD>"},
		{"(ibs)", "std::tuple<int32_t, bool, std::string>"},
		{"((i))", "std::tuple<std::tuple<int32_t>>"},
	}

	for _, tc := range cases {
		typ, err := dbustype.Parse(tc.input)
		if err != nil {
			t.Fatalf("Parse(%q) got error, want nil: %v", tc.input, err)
		}
		got := typ.BaseType()
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("getting the base type of %q failed\n(-got +want):\n%s", tc.input, diff)
		}
	}

	manyNestedCases := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaai",
		"((((((((((((((((((((((((((((((((i))))))))))))))))))))))))))))))))",
	}
	for _, tc := range manyNestedCases {
		if _, err := dbustype.Parse(tc); err != nil {
			t.Fatalf("Parse(%q) got error, want nil: %v", tc, err)
		}
	}
}

// Scalar types should not have reference behavior when used as in-args, and
// should just produce the base type as their in-arg type.
func TestInArgScalarTypes(t *testing.T) {
	cases := []string{
		"b", "y", "d", "n", "i", "x", "q", "u", "t",
	}
	for _, tc := range cases {
		typ, err := dbustype.Parse(tc)
		if err != nil {
			t.Fatalf("Parse(%q) got error, want nil: %v", tc, err)
		}
		got := typ.InArgType()
		want := typ.BaseType()
		if got != want {
			t.Fatalf("typ.BaseType() and typ.InArgType() mismatch, typ is %q", tc)
		}
	}
}

// Non-scalar types should have const reference behavior when used as in-args.
// The references should not be nested.
func TestInArgNonScalarTypes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"o", "const dbus::ObjectPath&"},
		{"s", "const std::string&"},
		{"h", "const base::ScopedFD&"},
		{"v", "const brillo::Any&"},
		{"ab", "const std::vector<bool>&"},
		{"ay", "const std::vector<uint8_t>&"},
		{"aay", "const std::vector<std::vector<uint8_t>>&"},
		{"ao", "const std::vector<dbus::ObjectPath>&"},
		{"ah", "const std::vector<base::ScopedFD>&"},
		{"a{oa{sa{sv}}}",
			"const std::map<dbus::ObjectPath, std::map<std::string, brillo::VariantDictionary>>&"},
		{"a{os}", "const std::map<dbus::ObjectPath, std::string>&"},
		{"a{ih}", "const std::map<int32_t, base::ScopedFD>&"},
		{"as", "const std::vector<std::string>&"},
		{"a{ss}", "const std::map<std::string, std::string>&"},
		{"a{sa{ss}}",
			"const std::map<std::string, std::map<std::string, std::string>>&"},
		{"a{sa{sv}}",
			"const std::map<std::string, brillo::VariantDictionary>&"},
		{"a{sv}", "const brillo::VariantDictionary&"},
		{"at", "const std::vector<uint64_t>&"},
		{"a{iv}", "const std::map<int32_t, brillo::Any>&"},
		{"(ib)", "const std::tuple<int32_t, bool>&"},
		{"(ih)", "const std::tuple<int32_t, base::ScopedFD>&"},
		{"(ibs)", "const std::tuple<int32_t, bool, std::string>&"},
		{"((i))", "const std::tuple<std::tuple<int32_t>>&"},
	}

	for _, tc := range cases {
		typ, err := dbustype.Parse(tc.input)
		if err != nil {
			t.Fatalf("Parse(%q) got error, want nil: %v", tc.input, err)
		}
		got := typ.InArgType()
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("getting the in arg type of %q failed\n(-got +want):\n%s", tc.input, diff)
		}
	}
}

// Out-args should be pointers, but only at the top level.
func TestOutArgTypes(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"b", "bool*"},
		{"y", "uint8_t*"},
		{"i", "int32_t*"},
		{"t", "uint64_t*"},
		{"o", "dbus::ObjectPath*"},
		{"s", "std::string*"},
		{"h", "base::ScopedFD*"},
		{"v", "brillo::Any*"},
		{"ab", "std::vector<bool>*"},
		{"ay", "std::vector<uint8_t>*"},
		{"aay", "std::vector<std::vector<uint8_t>>*"},
		{"ao", "std::vector<dbus::ObjectPath>*"},
		{"ah", "std::vector<base::ScopedFD>*"},
		{"a{oa{sa{sv}}}",
			"std::map<dbus::ObjectPath, std::map<std::string, brillo::VariantDictionary>>*"},
		{"a{os}", "std::map<dbus::ObjectPath, std::string>*"},
		{"a{ih}", "std::map<int32_t, base::ScopedFD>*"},
		{"as", "std::vector<std::string>*"},
		{"a{ss}", "std::map<std::string, std::string>*"},
		{"a{sa{ss}}",
			"std::map<std::string, std::map<std::string, std::string>>*"},
		{"a{sa{sv}}",
			"std::map<std::string, brillo::VariantDictionary>*"},
		{"a{sv}", "brillo::VariantDictionary*"},
		{"at", "std::vector<uint64_t>*"},
		{"a{iv}", "std::map<int32_t, brillo::Any>*"},
		{"(ib)", "std::tuple<int32_t, bool>*"},
		{"(ih)", "std::tuple<int32_t, base::ScopedFD>*"},
		{"(ibs)", "std::tuple<int32_t, bool, std::string>*"},
		{"((i))", "std::tuple<std::tuple<int32_t>>*"},
	}

	for _, tc := range cases {
		typ, err := dbustype.Parse(tc.input)
		if err != nil {
			t.Fatalf("Parse(%q) got error, want nil: %v", tc.input, err)
		}
		got := typ.OutArgType()
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("getting the out arg type of %q failed\n(-got +want):\n%s", tc.input, diff)
		}
	}
}

// TODO(chromium:983008): Add tests for PropertyType.
