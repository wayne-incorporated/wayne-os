// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package genutil_test

import (
	"testing"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateHeaderGuard(t *testing.T) {
	got := genutil.GenerateHeaderGuard("/foo/bar3_BAZ/adaptor.h")
	want := "____CHROMEOS_DBUS_BINDING___FOO_BAR3_BAZ_ADAPTOR_H"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("GenerateHeaderGuard diff (-got +want):\n%s", diff)
	}
}

func TestMakeInterfaceName(t *testing.T) {
	got := genutil.MakeInterfaceName("foo.bar.BazQux")
	want := "BazQuxInterface"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("MakeInterfaceName diff (-got +want):\n%s", diff)
	}
}

func TestMakeAdaptorName(t *testing.T) {
	got := genutil.MakeAdaptorName("foo.bar.BazQux")
	want := "BazQuxAdaptor"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("MakeAdaptorName diff (-got +want):\n%s", diff)
	}
}

func TestMakeProxyName(t *testing.T) {
	got := genutil.MakeProxyName("foo.bar.BazQux")
	want := "BazQuxProxy"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("MakeProxyName diff (-got +want):\n%s", diff)
	}
}

func TestMakeFullItfName(t *testing.T) {
	got := genutil.MakeFullItfName("foo.bar.BazQux")
	want := "foo::bar::BazQux"
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("MakeFullItfName diff (-got +want):\n%s", diff)
	}
}

func TestExtractNameSpaces(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{input: "foo", want: []string{}},
		{input: "foo.bar.BazQux", want: []string{"foo", "bar"}},
	}

	for _, tc := range cases {
		got := genutil.ExtractNameSpaces(tc.input)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Wrong result in ExtractNameSpaces(%q): diff (-got +want):\n%s", tc.input, diff)
		}
	}
}

func TestReverse(t *testing.T) {
	cases := []struct {
		input, want []string
	}{
		{input: []string{}, want: []string{}},
		{input: []string{"foo"}, want: []string{"foo"}},
		{input: []string{"foo", "bar"}, want: []string{"bar", "foo"}},
	}

	for _, tc := range cases {
		got := genutil.Reverse(tc.input)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Wrong result in Reverse(%q): diff (-got +want):\n%s", tc.input, diff)
		}
	}
}

func TestNindent(t *testing.T) {
	cases := []struct {
		n           int
		input, want string
	}{
		{n: 0, input: "", want: "\n"},
		{n: 1, input: "", want: "\n "},
		{n: 1, input: "abc\ndef", want: "\n abc\n def"},
	}

	for _, tc := range cases {
		got := genutil.Nindent(tc.n, tc.input)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Wrong result in Nindent(%q): diff (-got +want):\n%s", tc.input, diff)
		}
	}
}

func TestFormatComment(t *testing.T) {
	cases := []struct {
		indent int
		input  introspect.DocString
		want   string
	}{
		{2, "", ""},
		{2, " \tcomment\t ", "  // comment\n"},
		{2, "  \n \t  \n", ""},
		{
			indent: 0,
			input: `

    line1

    line2


	`,
			want: `// line1
//
// line2
`,
		}, {
			indent: 2,
			input: `
    line1
      - bullet1
        line2
      - bullet2
  line3
`,
			want: `  // line1
  //   - bullet1
  //     line2
  //   - bullet2
  // line3
`,
		},
	}

	for _, tc := range cases {
		got := genutil.FormatComment(tc.input, tc.indent)
		if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Wrong result in FormatComment(%q, %d): diff (-got +want):\n%s",
				tc.input, tc.indent, diff)
		}
	}
}

func TestArgName(t *testing.T) {
	cases := []struct {
		prefix, argName, want string
		argIndex              int
	}{
		{prefix: "in", argName: "", argIndex: 1, want: "in_1"},
		{prefix: "out", argName: "ret", argIndex: 3, want: "out_ret"},
	}

	for _, tc := range cases {
		got := genutil.ArgName(tc.prefix, tc.argName, tc.argIndex)
		if got != tc.want {
			t.Errorf("Wrong result in ArgName(%q, %q, %d):\ngot %s, want %s",
				tc.prefix, tc.argName, tc.argIndex, got, tc.want)
		}
	}
}

func TestMakeVariableName(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"foo.bar.FooBar", "foo_bar"},
		{"foo", "foo"},
		{"fooBarBaz", "foo_bar_baz"},
		{"UUID", "uuid"},
		{"FOObarBAZ", "foobar_baz"},
	}

	for _, tc := range cases {
		got := genutil.MakeVariableName(tc.input)
		if got != tc.want {
			t.Errorf("Wrong result in MakeVariableName(%q):\ngot %s, want %s", tc.input, got, tc.want)
		}
	}
}
