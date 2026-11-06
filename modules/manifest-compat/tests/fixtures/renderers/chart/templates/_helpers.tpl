{{- define "demo.labels" -}}
app.kubernetes.io/name: demo
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
