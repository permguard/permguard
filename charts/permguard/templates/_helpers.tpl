{{/*
Copyright (c) 2022 Nitro Agility S.r.l.
SPDX-License-Identifier: Apache-2.0
*/}}

{{- define "permguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "permguard.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "permguard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Labels on every object. */}}
{{- define "permguard.labels" -}}
helm.sh/chart: {{ include "permguard.chart" . }}
app.kubernetes.io/name: {{ include "permguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: permguard
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* The labels a selector matches on: only the ones that never change for a running release. */}}
{{- define "permguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "permguard.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "permguard.componentLabels" -}}
{{ include "permguard.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "permguard.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "permguard.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* An image reference, with the chart's appVersion as the tag unless one is set. */}}
{{- define "permguard.image" -}}
{{- $registry := .root.Values.image.registry -}}
{{- $tag := default .root.Chart.AppVersion .root.Values.image.tag -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
The probes. Both point at the telemetry port, never at the public one: probing the port that faces
the world means a load balancer's health check and a client's request share a connection limit, and
the first thing that fails under load is the check that says whether anything is wrong.
*/}}
{{- define "permguard.probes" -}}
{{- $probes := .root.Values.probes -}}
livenessProbe:
  httpGet:
    path: {{ $probes.liveness.path }}
    port: telemetry
  initialDelaySeconds: {{ $probes.liveness.initialDelaySeconds }}
  periodSeconds: {{ $probes.liveness.periodSeconds }}
  timeoutSeconds: {{ $probes.liveness.timeoutSeconds }}
  failureThreshold: {{ $probes.liveness.failureThreshold }}
readinessProbe:
  httpGet:
    path: {{ $probes.readiness.path }}
    port: telemetry
  initialDelaySeconds: {{ $probes.readiness.initialDelaySeconds }}
  periodSeconds: {{ $probes.readiness.periodSeconds }}
  timeoutSeconds: {{ $probes.readiness.timeoutSeconds }}
  failureThreshold: {{ $probes.readiness.failureThreshold }}
{{- if $probes.startup.enabled }}
startupProbe:
  httpGet:
    path: {{ $probes.startup.path }}
    port: telemetry
  periodSeconds: {{ $probes.startup.periodSeconds }}
  failureThreshold: {{ $probes.startup.failureThreshold }}
{{- end }}
{{- end -}}

{{/* The scrape annotations, for a Prometheus that reads them rather than a ServiceMonitor. */}}
{{- define "permguard.metricsAnnotations" -}}
{{- if .root.Values.metrics.annotations }}
prometheus.io/scrape: "true"
prometheus.io/path: /metrics
prometheus.io/port: {{ .telemetryPort | quote }}
{{- end }}
{{- end -}}

{{/*
Whether one component keeps its state on a PersistentVolume.

`persistence.enabled` is the default for every component, and a component may override it —
because one switch cannot express what a real installation needs: a control plane holds authority
and wants a volume, while a replicated data plane is a mirror and must NOT share one with its own
replicas. Takes `(dict "root" $ "plane" $plane)`, answers "true" or "".
*/}}
{{- define "permguard.persists" -}}
{{- $plane := .plane -}}
{{- $default := .root.Values.persistence.enabled -}}
{{- if and $plane $plane.persistence (kindIs "bool" $plane.persistence.enabled) -}}
{{- if $plane.persistence.enabled }}true{{ end -}}
{{- else -}}
{{- if $default }}true{{ end -}}
{{- end -}}
{{- end -}}

{{/*
This release's own control plane, in the cluster.

The Service is named after the release, so only a template knows the address — which is why a
values file that wrote one was right for exactly one release name. `http`, because the chart has
no certificate to point at; a deployment that does not trust its own network sets `servers`
explicitly with `https` and the authority to check.
*/}}
{{/*
Where a component tells the world to reach it.

A pod binds `0.0.0.0` — it has to, or it answers only itself — and `0.0.0.0` is not an address
anything can dial. So the discovery documents must publish something else, and in a cluster the
something else is the Service: stable, resolvable from every namespace, and named after the
release, which is why only a template can write it.

`advertisedUrl` overrides it, for the deployment reached through an Ingress or a load balancer
under its own hostname. Nothing is derived from `Host` or `X-Forwarded-*`: a header a caller
controls must not decide what this deployment publishes about itself.
*/}}
{{- define "permguard.advertisedUrl" -}}
{{- $component := .component -}}
{{- $root := .root -}}
{{- $plane := ternary $root.Values.controlPlane $root.Values.dataPlane (eq $component "control-plane") -}}
{{- if $plane.advertisedUrl -}}
{{ $plane.advertisedUrl | trimSuffix "/" }}
{{- else -}}
{{- $scheme := ternary "https" "http" (dig "public" "http" "tls" "enabled" false $plane.extraConfig) -}}
{{ $scheme }}://{{ include "permguard.fullname" $root }}-{{ $component }}:{{ $plane.ports.http }}
{{- end -}}
{{- end -}}

{{- define "permguard.controlPlaneUrl" -}}
{{- if .Values.allInOne.enabled -}}
http://{{ include "permguard.fullname" . }}-all-in-one:{{ .Values.allInOne.ports.controlHttp }}
{{- else -}}
http://{{ include "permguard.fullname" . }}-control-plane:{{ .Values.controlPlane.ports.http }}
{{- end -}}
{{- end -}}
