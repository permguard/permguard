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
the `permguard.image` dict, with an optional `name` for a second image the Pod runs; renders a list
item, or nothing.
*/}}
{{- define "permguard.verifyImage" -}}
{{- $iv := .root.Values.imageVerification -}}
{{- if $iv.enabled }}
- name: {{ .name | default "verify-image" }}
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

{{/*
What every Host of the release declares of its storage, backups and service objectives (TS-5), as
configuration: `hostControls.storage` is the `storage` section, `hostControls.backup` the
`operations.backup` section and `hostControls.objectives` the `objectives` section. A unit's
`extraConfig` is merged over it.
*/}}
{{- define "permguard.hostControlsConfig" -}}
{{- $controls := .Values.hostControls | default dict }}
{{- $config := dict }}
{{- with $controls.storage }}{{- $_ := set $config "storage" (deepCopy .) }}{{- end }}
{{- with $controls.backup }}{{- $_ := set $config "operations" (dict "backup" (deepCopy .)) }}{{- end }}
{{- with $controls.objectives }}{{- $_ := set $config "objectives" (deepCopy .) }}{{- end }}
{{- toYaml $config }}
{{- end }}

{{/*
Whether a unit's Host makes its identity offline, before its first start: every profile but
`development` (TS-10). Takes `(dict "assurance" $unit.assurance)`; answers "true" or nothing.
*/}}
{{- define "permguard.provisionsIdentity" -}}
{{- if ne (toString (dig "profile" "production" (.assurance | default dict))) "development" }}true{{ end }}
{{- end }}

{{/*
The init container that makes a Host's identity where `production` requires it made offline
(TS-10, `1-architecture/11` The Host identity under `production`): the release's command line,
on a volume that has no identity, in the custody the Host's own configuration names, its witness
printed to this container's log; on a volume that has one, it changes and prints nothing. Takes
`(dict "root" $ "resources" … "extraEnv" … "extraVolumeMounts" … "publicTls" bool "hostTls" bool)`;
runs after the claim. It mounts what the server mounts, since it checks the configuration the
server starts with, its TLS material included. Under `imageVerification` the command line's image
is verified first, by its own `verify-cli` (TD-4).
*/}}
{{- define "permguard.identityInit" -}}
{{- $cli := dict "root" .root "repository" .root.Values.cli.repository "digest" .root.Values.cli.digest "name" "verify-cli" }}
{{- with include "permguard.verifyImage" $cli | trim }}
{{ . }}
{{- end }}
- name: identity
  image: {{ include "permguard.image" $cli }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args: ["host", "identity", "provision", "--if-missing", "--volume", "/var/lib/permguard/volume", "--server-config", "/etc/permguard/config.yml"]
  {{- with .extraEnv }}
  env:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
    {{- toYaml .root.Values.securityContext | nindent 4 }}
  resources:
    {{- toYaml .resources | nindent 4 }}
  volumeMounts:
    - name: config
      mountPath: /etc/permguard
      readOnly: true
    - name: state
      mountPath: /var/lib/permguard
    - name: tmp
      mountPath: /tmp
    {{- if .publicTls }}
    - name: public-tls
      mountPath: /etc/permguard-tls
      readOnly: true
    {{- end }}
    {{- if .hostTls }}
    - name: host-tls
      mountPath: /etc/permguard-host-tls
      readOnly: true
    {{- end }}
    {{- with .extraVolumeMounts }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
{{- end }}

{{/*
The Authority Plane's listener (`2-security/8`): REST and gRPC on one port, under `tls` when given.
*/}}
{{- define "permguard.authorityListener" -}}
{{- $http := dict "enabled" true "addr" (printf "0.0.0.0:%d" (int .port)) }}
{{- $grpc := dict "enabled" true "addr" (printf "0.0.0.0:%d" (int .port)) }}
{{- with .tls }}
{{- $_ := set $http "tls" . }}
{{- $_ := set $grpc "tls" . }}
{{- end }}
{{- toYaml (dict "public" (dict "http" $http "grpc" $grpc)) }}
{{- end -}}

{{/*
Where the cluster's Authority Plane is reached, and what every token names as its issuer: the
control plane's, or the all-in-one's, Service on its authority port; `dataPlane.authority.url` when
the Authority Plane runs elsewhere.
*/}}
{{- define "permguard.authorityUrl" -}}
{{- if and .Values.dataPlane.authority.url (not .Values.allInOne.enabled) -}}
{{ .Values.dataPlane.authority.url | trimSuffix "/" }}
{{- else if .Values.allInOne.enabled -}}
{{- $scheme := ternary "https" "http" (not (empty .Values.allInOne.tls.secretName)) -}}
{{ $scheme }}://{{ include "permguard.fullname" . }}-all-in-one:{{ .Values.allInOne.ports.authority }}
{{- else -}}
{{- $scheme := ternary "https" "http" (not (empty .Values.controlPlane.tls.secretName)) -}}
{{ $scheme }}://{{ include "permguard.fullname" . }}-control-plane:{{ .Values.controlPlane.ports.authority }}
{{- end -}}
{{- end -}}

