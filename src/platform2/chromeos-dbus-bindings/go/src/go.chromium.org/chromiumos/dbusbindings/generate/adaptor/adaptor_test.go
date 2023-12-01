// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package adaptor

import (
	"bytes"
	"testing"
	"text/template"

	"go.chromium.org/chromiumos/dbusbindings/introspect"

	"github.com/google/go-cmp/cmp"
)

const (
	generateAdaptorsOutput = `// Automatic generation of D-Bus interfaces:
//  - fi.w1.wpa_supplicant1.Interface
//  - EmptyInterface
#ifndef ____CHROMEOS_DBUS_BINDING___TMP_ADAPTOR_H
#define ____CHROMEOS_DBUS_BINDING___TMP_ADAPTOR_H
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <base/files/scoped_file.h>
#include <dbus/object_path.h>
#include <brillo/any.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/exported_object_manager.h>
#include <brillo/variant_dictionary.h>

namespace fi {
namespace w1 {
namespace wpa_supplicant1 {

// Interface definition for fi::w1::wpa_supplicant1::Interface.
// interface doc
class InterfaceInterface {
 public:
  virtual ~InterfaceInterface() = default;

  virtual bool Scan(
      brillo::ErrorPtr* error,
      const std::vector<base::ScopedFD>& in_args) = 0;
  // method doc
  virtual void PassMeProtos(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>> response,
      const PassMeProtosRequest& in_request) = 0;
};

// Interface adaptor for fi::w1::wpa_supplicant1::Interface.
class InterfaceAdaptor {
 public:
  InterfaceAdaptor(InterfaceInterface* interface) : interface_(interface) {}
  InterfaceAdaptor(const InterfaceAdaptor&) = delete;
  InterfaceAdaptor& operator=(const InterfaceAdaptor&) = delete;

  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("fi.w1.wpa_supplicant1.Interface");

    itf->AddSimpleMethodHandlerWithError(
        "Scan",
        base::Unretained(interface_),
        &InterfaceInterface::Scan);
    itf->AddMethodHandler(
        "PassMeProtos",
        base::Unretained(interface_),
        &InterfaceInterface::PassMeProtos);

    signal_BSSRemoved_ = itf->RegisterSignalOfType<SignalBSSRemovedType>("BSSRemoved");

    itf->AddProperty(CapabilitiesName(), &capabilities_);
    itf->AddProperty(ClassName(), &bluetooth_class_);
  }

  // signal doc
  void SendBSSRemovedSignal(
      const YetAnotherProto& in_BSSDetail1,
      const std::tuple<int32_t, base::ScopedFD>& in_BSSDetail2) {
    auto signal = signal_BSSRemoved_.lock();
    if (signal)
      signal->Send(in_BSSDetail1, in_BSSDetail2);
  }

  // property doc
  static const char* CapabilitiesName() { return "Capabilities"; }
  brillo::VariantDictionary GetCapabilities() const {
    return capabilities_.GetValue().Get<brillo::VariantDictionary>();
  }
  void SetCapabilities(const brillo::VariantDictionary& capabilities) {
    capabilities_.SetValue(capabilities);
  }

  // property doc
  static const char* ClassName() { return "Class"; }
  uint32_t GetClass() const {
    return bluetooth_class_.GetValue().Get<uint32_t>();
  }
  void SetClass(uint32_t bluetooth_class) {
    bluetooth_class_.SetValue(bluetooth_class);
  }

  static dbus::ObjectPath GetObjectPath() {
    return dbus::ObjectPath{"/org/chromium/Test"};
  }

  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"fi.w1.wpa_supplicant1.Interface\">\n"
        "    <method name=\"Scan\">\n"
        "      <arg name=\"args\" type=\"ah\" direction=\"in\"/>\n"
        "    </method>\n"
        "    <method name=\"PassMeProtos\">\n"
        "      <arg name=\"request\" type=\"ay\" direction=\"in\"/>\n"
        "    </method>\n"
        "    <signal name=\"BSSRemoved\">\n"
        "      <arg name=\"BSSDetail1\" type=\"ay\"/>\n"
        "      <arg name=\"BSSDetail2\" type=\"(ih)\"/>\n"
        "    </signal>\n"
        "  </interface>\n";
  }

 private:
  using SignalBSSRemovedType = brillo::dbus_utils::DBusSignal<
      YetAnotherProto /*BSSDetail1*/,
      std::tuple<int32_t, base::ScopedFD> /*BSSDetail2*/>;
  std::weak_ptr<SignalBSSRemovedType> signal_BSSRemoved_;

  brillo::dbus_utils::ExportedProperty<brillo::VariantDictionary> capabilities_;
  brillo::dbus_utils::ExportedProperty<uint32_t> bluetooth_class_;

  InterfaceInterface* interface_;  // Owned by container of this adapter.
};

}  // namespace wpa_supplicant1
}  // namespace w1
}  // namespace fi


// Interface definition for EmptyInterface.
class EmptyInterfaceInterface {
 public:
  virtual ~EmptyInterfaceInterface() = default;
};

// Interface adaptor for EmptyInterface.
class EmptyInterfaceAdaptor {
 public:
  EmptyInterfaceAdaptor(EmptyInterfaceInterface* /* interface */) {}
  EmptyInterfaceAdaptor(const EmptyInterfaceAdaptor&) = delete;
  EmptyInterfaceAdaptor& operator=(const EmptyInterfaceAdaptor&) = delete;

  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("EmptyInterface");
  }

  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"EmptyInterface\">\n"
        "  </interface>\n";
  }

 private:
};

#endif  // ____CHROMEOS_DBUS_BINDING___TMP_ADAPTOR_H
`
)

func TestGenerateAdaptors(t *testing.T) {
	itf := introspect.Interface{
		Name: "fi.w1.wpa_supplicant1.Interface",
		Methods: []introspect.Method{
			{
				Name: "Scan",
				Args: []introspect.MethodArg{
					{
						Name: "args",
						Type: "ah",
					},
				},
			}, {
				Name: "PassMeProtos",
				Args: []introspect.MethodArg{
					{
						Name:      "request",
						Type:      "ay",
						Direction: "in",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "PassMeProtosRequest",
						},
					},
				},
				Annotations: []introspect.Annotation{
					{
						Name:  "org.chromium.DBus.Method.Kind",
						Value: "async",
					},
				},
				DocString: "\n        method doc\n      ",
			},
		},
		Signals: []introspect.Signal{
			{
				Name: "BSSRemoved",
				Args: []introspect.SignalArg{
					{
						Name: "BSSDetail1",
						Type: "ay",
						Annotation: introspect.Annotation{
							Name:  "org.chromium.DBus.Argument.ProtobufClass",
							Value: "YetAnotherProto",
						},
					}, {
						Name: "BSSDetail2",
						Type: "(ih)",
					},
				},
				DocString: "\n        signal doc\n      ",
			},
		},
		Properties: []introspect.Property{
			{
				Name:      "Capabilities",
				Type:      "a{sv}",
				Access:    "read",
				DocString: "\n        property doc\n      ",
			}, {
				Name:      "Class",
				Type:      "u",
				Access:    "read",
				DocString: "\n        property doc\n      ",
				Annotation: introspect.Annotation{
					Name:  "org.chromium.DBus.Argument.VariableName",
					Value: "bluetooth_class",
				},
			},
		},
		DocString: "\n      interface doc\n    ",
	}

	emptyItf := introspect.Interface{
		Name: "EmptyInterface",
	}

	introspections := []introspect.Introspection{
		{
			Name:       "/org/chromium/Test",
			Interfaces: []introspect.Interface{itf},
		}, {
			Interfaces: []introspect.Interface{emptyItf},
		},
	}

	out := new(bytes.Buffer)
	if err := Generate(introspections, out, "/tmp/adaptor.h"); err != nil {
		t.Fatalf("Generate got error, want nil: %v", err)
	}

	if diff := cmp.Diff(out.String(), generateAdaptorsOutput); diff != "" {
		t.Errorf("Generate failed (-got +want):\n%s", diff)
	}
}

func TestInterfaceMethodsTempl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name: "itfWithNoMethod",
			},
			want: "",
		}, {
			input: introspect.Interface{
				Name: "itfWithMethodsWithComment",
				Methods: []introspect.Method{
					{
						Name:      "methodWithComment1",
						DocString: "this is comment1",
					}, {
						Name:      "methodWithComment2",
						DocString: "this is comment2",
					},
				},
			},
			want: `
  // this is comment1
  virtual bool methodWithComment1(
      brillo::ErrorPtr* error) = 0;
  // this is comment2
  virtual bool methodWithComment2(
      brillo::ErrorPtr* error) = 0;
`,
		}, {
			input: introspect.Interface{
				Name: "itfWithMethodWithNoArg",
				Methods: []introspect.Method{
					{
						Name: "methodWithNoArg",
						Args: []introspect.MethodArg{
							{Name: "onlyOutput", Direction: "out", Type: "i"},
						},
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
						},
					},
				},
			},
			want: `
  virtual int32_t methodWithNoArg() = 0;
`,
		}, {
			input: introspect.Interface{
				Name: "itfWithMethodWithArgs",
				Methods: []introspect.Method{
					{
						Name: "methodWithArgs",
						Args: []introspect.MethodArg{
							{Name: "n", Direction: "in", Type: "i"},
							{Name: "", Direction: "in", Type: "s"},
						},
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
						},
					},
				},
			},
			want: `
  virtual void methodWithArgs(
      int32_t in_n,
      const std::string& in_2) = 0;
`,
		}, {
			input: introspect.Interface{
				Name: "itfWithConstMethod",
				Methods: []introspect.Method{
					{
						Name: "methodWithArgs",
						Args: []introspect.MethodArg{
							{Name: "n", Direction: "in", Type: "i"},
						},
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Const", Value: "true"},
							{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
						},
					},
				},
			},
			want: `
  virtual void methodWithArgs(
      int32_t in_n) const = 0;
`,
		},
	}

	tmpl := template.Must(template.New("interfaceMethodsTempl").Funcs(funcMap).Parse(`{{template "interfaceMethodsTmpl" .}}`))
	if _, err := tmpl.Parse(interfaceMethodsTmpl); err != nil {
		t.Fatalf("interfaceMethodsTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("interfaceMethodsTempl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("interfaceMethodsTempl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestRegisterWithDBusObjectTmpl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name: "fi.w1.wpa_supplicant1.ItfA",
				Methods: []introspect.Method{
					{
						Name: "SMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
						},
					}, {
						Name: "SMessageMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "simple"},
							{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
						},
					}, {
						Name: "NMethod",
					}, {
						Name: "NMessageMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
						},
					}, {
						Name: "RMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "raw"},
						},
					}, {
						Name: "RMessageMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.chromium.DBus.Method.Kind", Value: "raw"},
							{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
						},
					}, {
						Name: "AMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.freedesktop.DBus.GLib.Async"},
						},
					}, {
						Name: "AMessageMethod",
						Annotations: []introspect.Annotation{
							{Name: "org.freedesktop.DBus.GLib.Async"},
							{Name: "org.chromium.DBus.Method.IncludeDBusMessage", Value: "true"},
						},
					},
				},
				Signals: []introspect.Signal{
					{Name: "FooSignal"}, {Name: "BarSignal"},
				},
				Properties: []introspect.Property{
					{Name: "FooProperty", Access: "write", Type: "i"},
					{Name: "BarProperty", Access: "readwrite", Type: "i"},
					{Name: "BazProperty", Access: "read", Type: "i"},
				},
			},
			want: `  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("fi.w1.wpa_supplicant1.ItfA");

    itf->AddSimpleMethodHandler(
        "SMethod",
        base::Unretained(interface_),
        &ItfAInterface::SMethod);
    itf->AddSimpleMethodHandler(
        "SMessageMethod",
        base::Unretained(interface_),
        &ItfAInterface::SMessageMethod);
    itf->AddSimpleMethodHandlerWithError(
        "NMethod",
        base::Unretained(interface_),
        &ItfAInterface::NMethod);
    itf->AddSimpleMethodHandlerWithErrorAndMessage(
        "NMessageMethod",
        base::Unretained(interface_),
        &ItfAInterface::NMessageMethod);
    itf->AddRawMethodHandler(
        "RMethod",
        base::Unretained(interface_),
        &ItfAInterface::RMethod);
    itf->AddRawMethodHandler(
        "RMessageMethod",
        base::Unretained(interface_),
        &ItfAInterface::RMessageMethod);
    itf->AddMethodHandler(
        "AMethod",
        base::Unretained(interface_),
        &ItfAInterface::AMethod);
    itf->AddMethodHandlerWithMessage(
        "AMessageMethod",
        base::Unretained(interface_),
        &ItfAInterface::AMessageMethod);

    signal_FooSignal_ = itf->RegisterSignalOfType<SignalFooSignalType>("FooSignal");
    signal_BarSignal_ = itf->RegisterSignalOfType<SignalBarSignalType>("BarSignal");

    foo_property_.SetAccessMode(
        brillo::dbus_utils::ExportedPropertyBase::Access::kWriteOnly);
    foo_property_.SetValidator(
        base::BindRepeating(&ItfAAdaptor::ValidateFooProperty,
                            base::Unretained(this)));
    itf->AddProperty(FooPropertyName(), &foo_property_);
    bar_property_.SetAccessMode(
        brillo::dbus_utils::ExportedPropertyBase::Access::kReadWrite);
    bar_property_.SetValidator(
        base::BindRepeating(&ItfAAdaptor::ValidateBarProperty,
                            base::Unretained(this)));
    itf->AddProperty(BarPropertyName(), &bar_property_);
    itf->AddProperty(BazPropertyName(), &baz_property_);
  }
`,
		}, {
			input: introspect.Interface{
				Name: "fi.w1.wpa_supplicant1.EmptyInterface",
			},
			want: `  void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("fi.w1.wpa_supplicant1.EmptyInterface");
  }
`,
		},
	}

	tmpl := template.Must(template.New("registerWithDBusObjectTmpl").Funcs(funcMap).Parse(`{{template "registerWithDBusObjectTmpl" .}}`))
	if _, err := tmpl.Parse(registerWithDBusObjectTmpl); err != nil {
		t.Fatalf("registerWithDBusObjectTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("registerWithDBusObjectTmpl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("registerWithDBusObjectTmpl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestSendSignalMethodsTmpl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name: "itfWithNoSignal",
			},
			want: "",
		}, {
			input: introspect.Interface{
				Name: "itfWithSignalWithNoArg",
				Signals: []introspect.Signal{
					{
						Name: "SignalWithNoArg",
						Args: nil,
					},
				},
			},
			want: `
  void SendSignalWithNoArgSignal() {
    auto signal = signal_SignalWithNoArg_.lock();
    if (signal)
      signal->Send();
  }
`,
		}, {
			input: introspect.Interface{
				Name: "itfWithSignalsWithArgs",
				Signals: []introspect.Signal{
					{
						Name: "Sig1",
						Args: []introspect.SignalArg{
							{
								Name: "a1",
								Type: "h",
							}, {
								Name: "",
								Type: "i",
							},
						},
						DocString: "this is comment1",
					}, {
						Name: "Sig2",
						Args: []introspect.SignalArg{
							{
								Name: "",
								Type: "ay",
								Annotation: introspect.Annotation{
									Name:  "org.chromium.DBus.Argument.ProtobufClass",
									Value: "MyProto",
								},
							},
						},
						DocString: "this is comment2",
					},
				},
			},
			want: `
  // this is comment1
  void SendSig1Signal(
      const base::ScopedFD& in_a1,
      int32_t in_2) {
    auto signal = signal_Sig1_.lock();
    if (signal)
      signal->Send(in_a1, in_2);
  }
  // this is comment2
  void SendSig2Signal(
      const MyProto& in_1) {
    auto signal = signal_Sig2_.lock();
    if (signal)
      signal->Send(in_1);
  }
`,
		},
	}

	tmpl := template.Must(template.New("sendSignalMethodsTmpl").Funcs(funcMap).Parse(`{{template "sendSignalMethodsTmpl" .}}`))
	if _, err := tmpl.Parse(sendSignalMethodsTmpl); err != nil {
		t.Fatalf("sendSignalMethodsTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("sendSignalMethodsTmpl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("sendSignalMethodsTmpl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestQuotedIntrospectionForInterfaceTmpl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name: "fi.w1.wpa_supplicant1.ItfA",
				Methods: []introspect.Method{
					{
						Name: "Mthd1",
						Args: []introspect.MethodArg{
							{
								Name: "Arg1",
								Type: "i",
							}, {
								Name:      "Arg2",
								Type:      "u",
								Direction: "out",
							}, {
								Name: "Arg3",
								Type: "s",
							}, {
								Name:      "Arg4",
								Type:      "y",
								Direction: "out",
							},
						},
					}, {
						Name: "EmptyMthd",
					},
				},
				Signals: []introspect.Signal{
					{
						Name: "Sig1",
						Args: []introspect.SignalArg{
							{
								Name: "Arg1",
								Type: "i",
							}, {
								Name: "Arg2",
								Type: "u",
							},
						},
					}, {
						Name: "EmptySig",
					},
				},
			},
			want: `  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"fi.w1.wpa_supplicant1.ItfA\">\n"
        "    <method name=\"Mthd1\">\n"
        "      <arg name=\"Arg1\" type=\"i\" direction=\"in\"/>\n"
        "      <arg name=\"Arg3\" type=\"s\" direction=\"in\"/>\n"
        "      <arg name=\"Arg2\" type=\"u\" direction=\"out\"/>\n"
        "      <arg name=\"Arg4\" type=\"y\" direction=\"out\"/>\n"
        "    </method>\n"
        "    <method name=\"EmptyMthd\">\n"
        "    </method>\n"
        "    <signal name=\"Sig1\">\n"
        "      <arg name=\"Arg1\" type=\"i\"/>\n"
        "      <arg name=\"Arg2\" type=\"u\"/>\n"
        "    </signal>\n"
        "    <signal name=\"EmptySig\">\n"
        "    </signal>\n"
        "  </interface>\n";
  }
`,
		}, {
			input: introspect.Interface{
				Name: "EmptyItf",
			},
			want: `  static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"EmptyItf\">\n"
        "  </interface>\n";
  }
`,
		},
	}

	tmpl := template.Must(template.New("quotedIntrospectionForInterfaceTmpl").Funcs(funcMap).Parse(`{{template "quotedIntrospectionForInterfaceTmpl" .}}`))
	if _, err := tmpl.Parse(quotedIntrospectionForInterfaceTmpl); err != nil {
		t.Fatalf("quotedIntrospectionForInterfaceTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("quotedIntrospectionForInterfaceTmpl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("quotedIntrospectionForInterfaceTmpl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestSignalDataMembersTmpl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name: "itfWithNoSignal",
			},
			want: "",
		}, {
			input: introspect.Interface{
				Name: "itfWithSignalWithNoArg",
				Signals: []introspect.Signal{
					{
						Name: "SignalWithNoArg",
						Args: nil,
					},
				},
			},
			want: `  using SignalSignalWithNoArgType = brillo::dbus_utils::DBusSignal<>;
  std::weak_ptr<SignalSignalWithNoArgType> signal_SignalWithNoArg_;

`,
		}, {
			input: introspect.Interface{
				Name: "itfWithSignalsWithArgs",
				Signals: []introspect.Signal{
					{
						Name: "Sig1",
						Args: []introspect.SignalArg{
							{
								Name: "a1",
								Type: "h",
							}, {
								Name: "",
								Type: "i",
							},
						},
					}, {
						Name: "Sig2",
						Args: []introspect.SignalArg{
							{
								Name: "",
								Type: "ay",
								Annotation: introspect.Annotation{
									Name:  "org.chromium.DBus.Argument.ProtobufClass",
									Value: "MyProto",
								},
							},
						},
					},
				},
			},
			want: `  using SignalSig1Type = brillo::dbus_utils::DBusSignal<
      base::ScopedFD /*a1*/,
      int32_t>;
  std::weak_ptr<SignalSig1Type> signal_Sig1_;

  using SignalSig2Type = brillo::dbus_utils::DBusSignal<
      MyProto>;
  std::weak_ptr<SignalSig2Type> signal_Sig2_;

`,
		},
	}

	tmpl := template.Must(template.New("signalDataMembersTmpl").Funcs(funcMap).Parse(`{{template "signalDataMembersTmpl" .}}`))
	if _, err := tmpl.Parse(signalDataMembersTmpl); err != nil {
		t.Fatalf("signalDataMembersTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("signalDataMembersTmpl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("signalDataMembersTmpl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}

func TestPropertyDataMembersTmpl(t *testing.T) {
	cases := []struct {
		input introspect.Interface
		want  string
	}{
		{
			input: introspect.Interface{
				Name:       "fi.w1.wpa_supplicant1.EmptyItf",
				Properties: nil,
			},
			want: "",
		}, {
			input: introspect.Interface{
				Name: "fi.w1.wpa_supplicant1.ItfA",
				Properties: []introspect.Property{
					{Name: "FooProperty", Access: "write", Type: "(is)"},
					{Name: "BarProperty", Access: "readwrite", Type: "ay"},
				},
			},
			want: `  brillo::dbus_utils::ExportedProperty<std::tuple<int32_t, std::string>> foo_property_;
  brillo::dbus_utils::ExportedProperty<std::vector<uint8_t>> bar_property_;

`,
		},
	}

	tmpl := template.Must(template.New("propertyDataMembersTmpl").Funcs(funcMap).Parse(`{{template "signalDataMembersTmpl" .}}`))
	if _, err := tmpl.Parse(propertyDataMembersTmpl); err != nil {
		t.Fatalf("propertyDataMembersTmpl parse got error, want nil: %v", err)
	}

	for _, tc := range cases {
		out := new(bytes.Buffer)
		if err := tmpl.Execute(out, tc.input); err != nil {
			t.Fatalf("propertyDataMembersTmpl execute got error, want nil: %v", err)
		}
		if diff := cmp.Diff(out.String(), tc.want); diff != "" {
			t.Errorf("propertyDataMembersTmpl execute faild, interface name is %s\n(-got +want):\n%s", tc.input.Name, diff)
		}
	}
}
