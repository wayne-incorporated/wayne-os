// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package proxy

import (
	"go.chromium.org/chromiumos/dbusbindings/introspect"
)

const proxyInterfaceTemplate = `{{define "proxyInterface" -}}
{{- with .Itf -}}
{{range extractNameSpaces .Name -}}
namespace {{.}} {
{{end}}
// Abstract interface proxy for {{makeFullItfName .Name}}.
{{formatComment .DocString 0 -}}
{{- $itfName := makeProxyName .Name | printf "%sInterface" -}}
class {{$itfName}} {
 public:
  virtual ~{{$itfName}}() = default;
{{- range .Methods}}
{{- $inParams := makeMethodParams 0 .InputArguments -}}
{{- $outParams := makeMethodParams (len .InputArguments) .OutputArguments}}

{{formatComment .DocString 2 -}}
{{"  "}}virtual bool {{.Name}}(
{{- range $inParams }}
      {{.Type}} {{.Name}},
{{- end}}
{{- range $outParams }}
      {{.Type}} {{.Name}},
{{- end}}
      brillo::ErrorPtr* error,
      int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) = 0;

{{formatComment .DocString 2 -}}
{{"  "}}virtual void {{.Name}}Async(
{{- range $inParams}}
      {{.Type}} {{.Name}},
{{- end}}
      {{makeMethodCallbackType .OutputArguments}} success_callback,
      base::OnceCallback<void(brillo::Error*)> error_callback,
      int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) = 0;
{{- end}}
{{- range .Signals}}

  virtual void Register{{.Name}}SignalHandler(
      {{- makeSignalCallbackType .Args | nindent 6}} signal_callback,
      dbus::ObjectProxy::OnConnectedCallback on_connected_callback) = 0;
{{- end}}
{{- if .Properties}}{{"\n"}}{{end}}
{{- range .Properties}}
{{- $name := makePropertyVariableName . | makeVariableName -}}
{{- $type := makeProxyInArgTypeProxy . }}
  static const char* {{.Name}}Name() { return "{{.Name}}"; }
  virtual {{$type}} {{$name}}() const = 0;
  virtual bool is_{{$name}}_valid() const = 0;
{{- if eq .Access "readwrite"}}
  virtual void set_{{$name}}({{$type}} value,
                   {{repeat " " (len $name)}} base::OnceCallback<void(bool)> callback) = 0;
{{- end}}
{{- end}}

  virtual const dbus::ObjectPath& GetObjectPath() const = 0;
  virtual dbus::ObjectProxy* GetObjectProxy() const = 0;
{{- if .Properties}}
{{if $.ObjectManagerName}}
  virtual void SetPropertyChangedCallback(
      const base::RepeatingCallback<void({{$itfName}}*, const std::string&)>& callback) = 0;
{{- else}}
  virtual void InitializeProperties(
      const base::RepeatingCallback<void({{$itfName}}*, const std::string&)>& callback) = 0;
{{- end}}
{{- end}}
};

{{range extractNameSpaces .Name | reverse -}}
}  // namespace {{.}}
{{end}}
{{- end}}
{{- end}}`

type proxyInterfaceArgs struct {
	Itf               introspect.Interface
	ObjectManagerName string
}

func makeProxyInterfaceArgs(itf introspect.Interface, omName string) proxyInterfaceArgs {
	return proxyInterfaceArgs{Itf: itf, ObjectManagerName: omName}
}
