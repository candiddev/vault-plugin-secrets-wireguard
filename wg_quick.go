package main

import (
	"strings"
	"text/template"
)

type wgQuickValues struct {
	Group *wireguardGroup
	Name  string
}

var wgQuickTemplate = template.Must(template.New("wgquick").Parse(strings.TrimSpace(`
# {{ .Group.Name }}/{{ .Name }}

{{ range .Group.Peers -}}
{{ if eq .Name $.Name -}}
[Interface]
Address={{ .IP }}
PrivateKey={{ .PrivateKey }}
{{- if .Port }}
ListenPort={{ .Port }}
{{- end }}
{{- else }}
# {{ .Name }}
[Peer]
PublicKey={{ .PublicKey }}
AllowedIPs={{ .AllowedIPs }}
{{- if .Port }}
Endpoint={{ .Hostname }}:{{ .Port }}
{{- else if .PersistentKeepalive }}
PersistentKeepalive={{ .PersistentKeepalive }}
{{- end }}
{{- end }}
{{ end }}
`)))
