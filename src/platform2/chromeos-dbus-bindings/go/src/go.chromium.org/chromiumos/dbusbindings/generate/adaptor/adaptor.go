// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package adaptor outputs a adaptor based on introspects.
package adaptor

import (
	"io"
	"text/template"

	"go.chromium.org/chromiumos/dbusbindings/generate/genutil"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

type templateArgs struct {
	Introspects []introspect.Introspection
	HeaderGuard string
}

var funcMap = template.FuncMap{
	"makeInterfaceName":       genutil.MakeInterfaceName,
	"makeAdaptorName":         genutil.MakeAdaptorName,
	"makeFullItfName":         genutil.MakeFullItfName,
	"extractNameSpaces":       genutil.ExtractNameSpaces,
	"formatComment":           genutil.FormatComment,
	"makeMethodRetType":       makeMethodRetType,
	"makeMethodParams":        makeMethodParams,
	"makeAddHandlerName":      makeAddHandlerName,
	"makePropertyWriteAccess": makePropertyWriteAccess,
	"makeVariableName":        genutil.MakeVariableName,
	"makeSignalParams":        makeSignalParams,
	"makeSignalArgNames":      makeSignalArgNames,
	"makePropertyVariableName": func(p *introspect.Property) string {
		return p.VariableName()
	},
	"makePropertyBaseTypeExtract": func(p *introspect.Property) (string, error) {
		return p.BaseType()
	},
	"makePropertyInArgTypeAdaptor": func(p *introspect.Property) (string, error) {
		return p.InArgType()
	},
	"makeDBusSignalParams": makeDBusSignalParams,
	"reverse":              genutil.Reverse,
}

const (
	templateText = `// Automatic generation of D-Bus interfaces:
{{range .Introspects}}{{range .Interfaces -}}
//  - {{.Name}}
{{end}}{{end -}}
#ifndef {{.HeaderGuard}}
#define {{.HeaderGuard}}
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
{{range $introspect := .Introspects}}{{range .Interfaces -}}
{{$itfName := makeInterfaceName .Name -}}
{{$className := makeAdaptorName .Name -}}
{{$fullItfName := makeFullItfName .Name}}
{{range extractNameSpaces .Name -}}
namespace {{.}} {
{{end}}
// Interface definition for {{$fullItfName}}.
{{formatComment .DocString 0 -}}
class {{$itfName}} {
 public:
  virtual ~{{$itfName}}() = default;
{{template "interfaceMethodsTmpl" . -}}
};

// Interface adaptor for {{$fullItfName}}.
class {{$className}} {
 public:
{{- if .Methods}}
  {{$className}}({{$itfName}}* interface) : interface_(interface) {}
{{- else}}
  {{$className}}({{$itfName}}* /* interface */) {}
{{- end}}
  {{$className}}(const {{$className}}&) = delete;
  {{$className}}& operator=(const {{$className}}&) = delete;

{{template "registerWithDBusObjectTmpl" . -}}
{{template "sendSignalMethodsTmpl" . -}}
{{template "propertyMethodImplementationTmpl" . -}}
{{if $introspect.Name}}
  static dbus::ObjectPath GetObjectPath() {
    return dbus::ObjectPath{"{{$introspect.Name}}"};
  }
{{end}}
{{template "quotedIntrospectionForInterfaceTmpl" . -}}
{{"\n "}}private:
{{template "signalDataMembersTmpl" . -}}
{{template "propertyDataMembersTmpl" . -}}
{{if .Methods -}}
{{"  "}}{{$itfName}}* interface_;  // Owned by container of this adapter.
{{end -}}
};

{{range extractNameSpaces .Name | reverse -}}
}  // namespace {{.}}
{{end -}}
{{end}}{{end -}}
#endif  // {{.HeaderGuard}}
`
	interfaceMethodsTmpl = `{{define "interfaceMethodsTmpl" -}}
{{if .Methods}}{{"\n"}}{{end -}}
{{range .Methods -}}
{{formatComment .DocString 2 -}}
{{"  "}}virtual {{makeMethodRetType .}} {{.Name}}(
{{- range $i, $arg := makeMethodParams .}}{{if ne $i 0}},{{end}}
      {{$arg -}}
{{end -}}
) {{if .Const}}const {{end}}= 0;
{{end -}}
{{end}}`

	registerWithDBusObjectTmpl = `{{define "registerWithDBusObjectTmpl" -}}
{{"  "}}void RegisterWithDBusObject(brillo::dbus_utils::DBusObject* object) {
    brillo::dbus_utils::DBusInterface* itf =
        object->AddOrGetInterface("{{.Name}}");
{{if .Methods}}{{"\n"}}{{end -}}
{{$itfName := makeInterfaceName .Name -}}
{{range .Methods -}}
{{"    "}}itf->{{makeAddHandlerName .}}(
        "{{.Name}}",
        base::Unretained(interface_),
        &{{$itfName}}::{{.Name}});
{{end -}}

{{if .Signals}}{{"\n"}}{{end -}}
{{range .Signals -}}
{{"    "}}signal_{{.Name}}_ = itf->RegisterSignalOfType<Signal{{.Name}}Type>("{{.Name}}");
{{end -}}

{{$adaptorName := makeAdaptorName .Name -}}
{{if .Properties}}{{"\n"}}{{end -}}
{{range .Properties -}}
{{$writeAccess := makePropertyWriteAccess . -}}
{{$variableName := makePropertyVariableName . | makeVariableName -}}
{{if $writeAccess -}} {{/* Register exported properties. */ -}}
{{"    "}}{{$variableName}}_.SetAccessMode(
        brillo::dbus_utils::ExportedPropertyBase::Access::{{$writeAccess}});
    {{$variableName}}_.SetValidator(
        base::BindRepeating(&{{$adaptorName}}::Validate{{.Name}},
                            base::Unretained(this)));
{{end -}}
{{"    "}}itf->AddProperty({{.Name}}Name(), &{{$variableName}}_);
{{end -}}

{{"  " -}} }
{{end}}`

	sendSignalMethodsTmpl = `{{define "sendSignalMethodsTmpl" -}}
{{if .Signals}}{{"\n"}}{{end -}}
{{range .Signals -}}
{{formatComment .DocString 2 -}}
{{"  "}}void Send{{.Name}}Signal(
{{- range $i, $arg := makeSignalParams .}}{{if ne $i 0}},{{end}}
      {{$arg -}}
{{end}}) {
    auto signal = signal_{{.Name}}_.lock();
    if (signal)
      signal->Send({{makeSignalArgNames .}});
  }
{{end -}}
{{end}}`

	propertyMethodImplementationTmpl = `{{define "propertyMethodImplementationTmpl" -}}
{{range .Properties}}{{"\n" -}}
{{$baseType := makePropertyBaseTypeExtract . -}}
{{$variableName := makePropertyVariableName . | makeVariableName -}}

{{/* Property name accessor. */ -}}
{{formatComment .DocString 2 -}}
{{"  "}}static const char* {{.Name}}Name() { return "{{.Name}}"; }

{{- /* Getter method. */}}
  {{$baseType}} Get{{.Name}}() const {
    return {{$variableName}}_.GetValue().Get<{{$baseType}}>();
  }

{{- /* Setter method. */}}
  void Set{{.Name}}({{makePropertyInArgTypeAdaptor .}} {{$variableName}}) {
    {{$variableName}}_.SetValue({{$variableName}});
  }

{{- /* Validation method for property with write access. */}}
{{if ne .Access "read" -}}
{{"  "}}virtual bool Validate{{.Name}}(
      {{- /* Explicitly specify the "value" parameter as const & to match the */}}
      {{- /* validator callback function signature. */}}
      brillo::ErrorPtr* /*error*/, const {{$baseType}}& /*value*/) {
    return true;
  }
{{end -}}
{{end -}}
{{end}}`

	quotedIntrospectionForInterfaceTmpl = `{{define "quotedIntrospectionForInterfaceTmpl" -}}
{{"  "}}static const char* GetIntrospectionXml() {
    return
        "  <interface name=\"{{.Name}}\">\n"
{{- range .Methods}}
        "    <method name=\"{{.Name}}\">\n"
{{- range .InputArguments}}
        "      <arg name=\"{{.Name}}\" type=\"{{.Type}}\" direction=\"in\"/>\n"
{{- end}}
{{- range .OutputArguments}}
        "      <arg name=\"{{.Name}}\" type=\"{{.Type}}\" direction=\"out\"/>\n"
{{- end}}
        "    </method>\n"
{{- end}}
{{- range .Signals}}
        "    <signal name=\"{{.Name}}\">\n"
{{- range .Args}}
        "      <arg name=\"{{.Name}}\" type=\"{{.Type}}\"/>\n"
{{- end}}
        "    </signal>\n"
{{- end}}
        "  </interface>\n";
  }
{{end}}`

	signalDataMembersTmpl = `{{define "signalDataMembersTmpl" -}}
{{range .Signals -}}
{{"  "}}using Signal{{.Name}}Type = brillo::dbus_utils::DBusSignal<
{{- range $i, $arg := makeDBusSignalParams .}}{{if ne $i 0}},{{end}}
      {{$arg -}}
{{end}}>;
  std::weak_ptr<Signal{{.Name}}Type> signal_{{.Name}}_;

{{end -}}
{{end}}`

	propertyDataMembersTmpl = `{{define "propertyDataMembersTmpl" -}}
{{range .Properties -}}
{{$variableName := makePropertyVariableName . | makeVariableName -}}
{{"  "}}brillo::dbus_utils::ExportedProperty<{{makePropertyBaseTypeExtract . }}> {{$variableName}}_;
{{end -}}
{{if .Properties}}{{"\n"}}{{end -}}
{{end}}`
)

// Generate prints an interface definition and an interface adaptor for each interface in introspects.
func Generate(introspects []introspect.Introspection, f io.Writer, outputFilePath string) error {
	tmpl, err := template.New("adaptor").Funcs(funcMap).Parse(templateText)
	if err != nil {
		return err
	}

	if _, err = tmpl.Parse(interfaceMethodsTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(registerWithDBusObjectTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(sendSignalMethodsTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(propertyMethodImplementationTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(quotedIntrospectionForInterfaceTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(signalDataMembersTmpl); err != nil {
		return err
	}
	if _, err = tmpl.Parse(propertyDataMembersTmpl); err != nil {
		return err
	}

	var headerGuard = genutil.GenerateHeaderGuard(outputFilePath)
	return tmpl.Execute(f, templateArgs{introspects, headerGuard})
}
