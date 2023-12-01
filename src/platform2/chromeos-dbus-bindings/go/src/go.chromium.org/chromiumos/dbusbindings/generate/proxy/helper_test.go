// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package proxy

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

func TestMakeMethodParams(t *testing.T) {
	cases := []struct {
		offset int
		args   []introspect.MethodArg
		want   []param
	}{{
		offset: 0,
		args: []introspect.MethodArg{{
			Name: "iarg1", Type: "i",
		}, {
			Name: "iarg2", Type: "h",
		}, {
			Name: "iarg3", Type: "o",
		}},
		want: []param{
			{Type: "int32_t", Name: "in_iarg1"},
			{Type: "const base::ScopedFD&", Name: "in_iarg2"},
			{Type: "const dbus::ObjectPath&", Name: "in_iarg3"},
		},
	}, {
		offset: 3,
		args: []introspect.MethodArg{{
			Type: "i",
		}, {
			Name: "iarg2", Type: "i",
		}, {
			Type: "i",
		}, {
			Name: "iarg4", Type: "i",
		}, {
			Type: "i",
		}},
		want: []param{
			{Type: "int32_t", Name: "in_4"},
			{Type: "int32_t", Name: "in_iarg2"},
			{Type: "int32_t", Name: "in_6"},
			{Type: "int32_t", Name: "in_iarg4"},
			{Type: "int32_t", Name: "in_8"},
		},
	}, {
		offset: 0,
		args: []introspect.MethodArg{{
			Name: "oarg1", Type: "i", Direction: "out",
		}, {
			Name: "oarg2", Type: "h", Direction: "out",
		}, {
			Name: "oarg3", Type: "o", Direction: "out",
		}},
		want: []param{
			{Type: "int32_t*", Name: "out_oarg1"},
			{Type: "base::ScopedFD*", Name: "out_oarg2"},
			{Type: "dbus::ObjectPath*", Name: "out_oarg3"},
		},
	}, {
		offset: 5,
		args: []introspect.MethodArg{{
			Type: "i", Direction: "out",
		}, {
			Name: "oarg2", Type: "i", Direction: "out",
		}, {
			Type: "i", Direction: "out",
		}, {
			Name: "oarg4", Type: "i", Direction: "out",
		}, {
			Type: "i", Direction: "out",
		}},
		want: []param{
			{Type: "int32_t*", Name: "out_6"},
			{Type: "int32_t*", Name: "out_oarg2"},
			{Type: "int32_t*", Name: "out_8"},
			{Type: "int32_t*", Name: "out_oarg4"},
			{Type: "int32_t*", Name: "out_10"},
		},
	}}

	for _, tc := range cases {
		got, err := makeMethodParams(tc.offset, tc.args)
		if err != nil {
			t.Errorf("Unexpected method params format error: %v", err)
		} else if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Unexpected method params format: got %v, want %v", got, tc.want)
		}
	}
}

func TestMakeMockMethodParams(t *testing.T) {
	cases := []struct {
		args []introspect.MethodArg
		want []string
	}{{
		args: []introspect.MethodArg{{
			Name: "iarg1", Type: "i",
		}, {
			Name: "iarg2", Type: "h",
		}, {
			Name: "iarg3", Type: "o",
		}},
		want: []string{
			"int32_t /*in_iarg1*/",
			"const base::ScopedFD& /*in_iarg2*/",
			"const dbus::ObjectPath& /*in_iarg3*/",
		},
	}, {
		args: []introspect.MethodArg{{
			Type: "i",
		}, {
			Name: "iarg2", Type: "i",
		}, {
			Type: "i",
		}, {
			Name: "iarg4", Type: "i",
		}, {
			Type: "i",
		}},
		want: []string{
			"int32_t",
			"int32_t /*in_iarg2*/",
			"int32_t",
			"int32_t /*in_iarg4*/",
			"int32_t",
		},
	}, {
		args: []introspect.MethodArg{{
			Name: "oarg1", Type: "i", Direction: "out",
		}, {
			Name: "oarg2", Type: "h", Direction: "out",
		}, {
			Name: "oarg3", Type: "o", Direction: "out",
		}},
		want: []string{
			"int32_t* /*out_oarg1*/",
			"base::ScopedFD* /*out_oarg2*/",
			"dbus::ObjectPath* /*out_oarg3*/",
		},
	}, {
		args: []introspect.MethodArg{{
			Type: "i", Direction: "out",
		}, {
			Name: "oarg2", Type: "i", Direction: "out",
		}, {
			Type: "i", Direction: "out",
		}, {
			Name: "oarg4", Type: "i", Direction: "out",
		}, {
			Type: "i", Direction: "out",
		}},
		want: []string{
			"int32_t*",
			"int32_t* /*out_oarg2*/",
			"int32_t*",
			"int32_t* /*out_oarg4*/",
			"int32_t*",
		},
	}}

	for _, tc := range cases {
		got, err := makeMockMethodParams(tc.args)
		if err != nil {
			t.Errorf("Unexpected method params format error: %v", err)
		} else if diff := cmp.Diff(got, tc.want); diff != "" {
			t.Errorf("Unexpected method params format: got %v, want %v", got, tc.want)
		}
	}
}

func TestMakeMethodCallbackType(t *testing.T) {
	cases := []struct {
		args []introspect.MethodArg
		want string
	}{{
		args: []introspect.MethodArg{},
		want: "base::OnceCallback<void()>",
	}, {
		args: []introspect.MethodArg{{
			Name: "arg1", Type: "ay", Direction: "out",
		}},
		want: "base::OnceCallback<void(const std::vector<uint8_t>& /*arg1*/)>",
	}, {
		args: []introspect.MethodArg{{
			Name: "arg1", Type: "i",
		}, {
			Name: "arg2", Type: "x",
		}, {
			Name: "arg3", Type: "(sh)",
		}},
		want: ("base::OnceCallback<void(int32_t /*arg1*/, " +
			"int64_t /*arg2*/, " +
			"const std::tuple<std::string, base::ScopedFD>& /*arg3*/)>"),
	}}

	for _, tc := range cases {
		got, err := makeMethodCallbackType(tc.args)
		if err != nil {
			t.Errorf("Unexpected method callback type format error: %v", err)
		} else if got != tc.want {
			t.Errorf("Unexpected method callback type format: got %v, want %v", got, tc.want)
		}
	}
}

func TestMakeSignalCallbackType(t *testing.T) {
	cases := []struct {
		args []introspect.SignalArg
		want string
	}{{
		args: []introspect.SignalArg{},
		want: "base::RepeatingClosure",
	}, {
		args: []introspect.SignalArg{{
			Type: "ay",
		}},
		want: "const base::RepeatingCallback<void(const std::vector<uint8_t>&)>&",
	}, {
		args: []introspect.SignalArg{{
			Type: "i",
		}, {
			Type: "x",
		}, {
			Type: "(sh)",
		}},
		want: ("const base::RepeatingCallback<void(int32_t,\n" +
			"                                   int64_t,\n" +
			"                                   const std::tuple<std::string, base::ScopedFD>&)>&"),
	}}

	for _, tc := range cases {
		got, err := makeSignalCallbackType(tc.args)
		if err != nil {
			t.Errorf("Unexpected signal callback type format error: %v", err)
		} else if got != tc.want {
			t.Errorf("Unexpected signal callback type format: got %v, want %v", got, tc.want)
		}
	}
}
