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

{{/*
An image reference: by its digest when `digest` names one (TD-4: what was verified is what runs),
else with the chart's appVersion as the tag unless one is set.
*/}}
{{- define "permguard.image" -}}
{{- $registry := .root.Values.image.registry -}}
{{- $name := .repository -}}
{{- if $registry -}}
{{- $name = printf "%s/%s" $registry .repository -}}
{{- end -}}
{{- if .digest -}}
{{- printf "%s@%s" $name .digest -}}
{{- else -}}
{{- printf "%s:%s" $name (default .root.Chart.AppVersion .root.Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
The `verify-image` init container (TD-4), first in every Permguard Pod when `imageVerification` is
on: `gh attestation verify` of the digest the Pod runs, under the release's provenance policy. Takes
the `permguard.image` dict; renders a list item, or nothing.
*/}}
{{- define "permguard.verifyImage" -}}
{{- $iv := .root.Values.imageVerification -}}
{{- if $iv.enabled }}
- name: verify-image
  image: {{ $iv.verifier.image }}
  imagePullPolicy: IfNotPresent
  args:
    - attestation
    - verify
    - {{ printf "oci://%s" (include "permguard.image" .) | quote }}
    - --repo
    - {{ $iv.repository | quote }}
    - --signer-workflow
    - {{ $iv.signerWorkflow | quote }}
    - --source-ref
    - {{ default (printf "refs/tags/v%s" .root.Chart.AppVersion) $iv.sourceRef | quote }}
    - --deny-self-hosted-runners
  env:
    - name: GH_TOKEN
      valueFrom:
        secretKeyRef:
          name: {{ $iv.tokenSecret.name }}
          key: {{ $iv.tokenSecret.key }}
    - name: HOME
      value: /tmp
    - name: GH_NO_UPDATE_NOTIFIER
      value: "1"
  securityContext:
    {{- toYaml .root.Values.securityContext | nindent 4 }}
  resources:
    {{- toYaml $iv.verifier.resources | nindent 4 }}
  volumeMounts:
    - name: verify-image-home
      mountPath: /tmp
{{- end }}
{{- end -}}

{{/* The verifier's writable home, beside a read-only root filesystem: a list item, or nothing. */}}
{{- define "permguard.verifyImageVolume" -}}
{{- if .Values.imageVerification.enabled }}
- name: verify-image-home
  emptyDir:
    sizeLimit: 16Mi
{{- end }}
{{- end -}}

{{/*
The probes. Both point at the Server Host operations port (still named `telemetry` in the stable
chart values), never at the public one: probing the port that faces the world means a load
balancer's health check and a client's request share a connection limit, and the first thing that
fails under load is the check that says whether anything is wrong.
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
{{/*
Whether a component keeps its state in a volume of its own, per replica.

# Why this is a switch and not a deduction

A volume per replica means a StatefulSet, and a Deployment cannot become a StatefulSet in place:
Kubernetes rejects the change, so an operator upgrading a release would have to delete the workload
and recreate it. Deducing the kind from "temporal and replicated" would make that happen to
somebody who only edited a replica count, which is not a decision a chart should take on their
behalf. So it is opted into, and `checks.yaml` refuses the combinations that need it without it.
*/}}
{{- define "permguard.perReplica" -}}
{{- if include "permguard.persists" (dict "root" .root "plane" .plane) -}}
{{- if .root.Values.persistence.perReplica }}true{{ end -}}
{{- end -}}
{{- end -}}

{{/*
The workload kind a component is deployed as.

A StatefulSet exactly when each replica needs its own volume: it is what gives a pod a stable name
and a claim that follows it across a reschedule. Everything else is a Deployment, because a
StatefulSet's ordered, one-at-a-time rollout is a cost with nothing to buy for a plane whose
replicas are interchangeable.
*/}}
{{- define "permguard.workloadKind" -}}
{{- if include "permguard.perReplica" (dict "root" .root "plane" .plane) -}}
StatefulSet
{{- else -}}
Deployment
{{- end -}}
{{- end -}}

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
{{- $scheme := ternary "https" "http" (or (not (empty $plane.tls.secretName)) (eq (toString (dig "public" "http" "tls" "enabled" false $plane.extraConfig)) "true")) -}}
{{ $scheme }}://{{ include "permguard.fullname" $root }}-{{ $component }}:{{ $plane.ports.http }}
{{- end -}}
{{- end -}}

{{/*
The TLS block of a public listener (WP-2.11), from a component's `tls` values: the mounted Secret's
certificate and key, or the declaration that an ingress or a sidecar terminates TLS in front of it.
Empty in neither case, which `checks.yaml` refuses outside `developmentMode`.
*/}}
{{- define "permguard.publicTls" -}}
{{- if .secretName }}
cert: /etc/permguard-tls/tls.crt
key: /etc/permguard-tls/tls.key
{{- else if .terminatedUpstream }}
terminated_upstream: true
{{- end }}
{{- end }}
