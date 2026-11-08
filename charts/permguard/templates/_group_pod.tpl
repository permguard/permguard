{{/*
Copyright (c) 2022 Nitro Agility S.r.l.
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
A group replica's Pod spec (TD-1, TD-2): the StatefulSet's or Deployment's, and the drain Job's.
Takes `(dict "root" $ "group" $g "dp" $dp "stateful" bool "claim" "" "recover" false)`: `claim`
names the claim a drain Job mounts in place of the claim template, `recover` makes the run a
recovery drain (`shutdown.recover_drain`), which never restarts.
*/}}
{{- define "permguard.groupPodSpec" -}}
{{- $root := .root -}}
{{- $g := .group -}}
{{- $dp := .dp -}}
{{- $stateful := .stateful }}
serviceAccountName: {{ include "permguard.serviceAccountName" $root }}
{{- with $root.Values.image.pullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
securityContext:
  {{- toYaml $root.Values.podSecurityContext | nindent 2 }}
# One budget: the `preStop` hook asks for the drain and returns, so the drain starts then,
# and the grace period is the process's `shutdown.timeout` plus the seconds the signal and the
# endpoint removal take, never a second budget after the hook.
terminationGracePeriodSeconds: {{ add $g.shutdown.timeoutSeconds 5 }}
{{- $image := dict "root" $root "repository" $dp.repository "digest" $dp.digest }}
{{- $provisions := include "permguard.provisionsIdentity" (dict "assurance" $g.assurance) }}
{{- if or $stateful .claim $provisions $root.Values.imageVerification.enabled }}
initContainers:
  {{- with include "permguard.verifyImage" $image | trim }}{{ . | nindent 2 }}{{- end }}
{{- end }}
{{- if or $stateful .claim }}
# The orchestrator's claim (WP-1.4): every Pod of a replica moves its volume's claim one
# generation forward before the server opens it, so a frame a previous Pod appends after that
# is recognised as a stale writer's. A container restart inside the same Pod keeps the claim:
# the process before it is gone, and its frames are not stale. From `production` a volume is
# served only under a claim. The volume directory is created inside the mount on the first
# Pod, by this container, for the server's user; the kubelet's fsGroup may add the server's own
# group to it, never anybody else.
  - name: claim
    image: {{ include "permguard.image" $image }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args: ["volume", "claim", "--volume", "/var/lib/permguard/volume", "--next", "--create"]
    securityContext:
      {{- toYaml $root.Values.securityContext | nindent 6 }}
    resources:
      {{- toYaml $g.resources | nindent 6 }}
    volumeMounts:
      - name: state
        mountPath: /var/lib/permguard
{{- end }}
{{- if $provisions }}
  {{- include "permguard.identityInit" (dict "root" $root "resources" $g.resources "extraEnv" $g.extraEnv "extraVolumeMounts" $dp.extraVolumeMounts "publicTls" $dp.tls.secretName "hostTls" $dp.hostListener.enabled) | nindent 2 }}
{{- end }}
containers:
  - name: data-plane
    image: {{ include "permguard.image" $image }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args: ["/etc/permguard/config.yml"]
    env:
      # The Host's volume is a directory inside the mount (the claim container creates it for a
      # volume, the server for an emptyDir), not the mount itself: a mounted volume's root belongs to root (an fsGroup changes its group, never
      # its owner), so a server running as 65532 could not make it private. The directory it
      # creates is its own, and it narrows it to 0700. Set here because the image's
      # environment names the mount, and the environment is read over the file.
      - name: PERMGUARD_WORKING_DIR
        value: /var/lib/permguard/volume
      {{- if and (not .recover) (or $provisions $g.join) }}
      # The replica's ordinal: what names its own invitations and its own witness.
      - name: POD_INDEX
        valueFrom:
          fieldRef:
            fieldPath: metadata.labels['apps.kubernetes.io/pod-index']
      {{- end }}
      {{- if $provisions }}
      # Its witness, the one its `identity` container printed, recorded by the operator in the
      # group's `-identity` ConfigMap; until it is, the replica refuses to start and says so. A
      # drain Job reads the witness of the ordinal whose claim it drains.
      - name: PERMGUARD_HOST_IDENTITY_WITNESS_FILE
        value: {{ ternary "/etc/permguard-identity/witness-__ORDINAL__" "/etc/permguard-identity/witness-$(POD_INDEX)" (eq (toString .recover) "true") | quote }}
      {{- end }}
      {{- with $g.join }}
      {{- if not $.recover }}
      # TD-5: the replica joins the control plane's Host by itself, from its own invitations, the
      # Secret's `<invitation>-<ordinal>`, its coordinator pinned apart from them. The approval stays
      # the coordinator's; a replica that joined never reads the file again.
      # One invitation per membership the `-membership` ConfigMap states, `control` and `data`.
      {{- $memberships := include "permguard.groupMemberships" $g | fromJson }}
      - name: PERMGUARD_HOST_JOIN_INVITATION_FILE
        value: {{ $files := list }}{{ range $name := (.invitations | default (ternary (list "control" "data") (list "control") (not (empty $memberships.data)))) }}{{ $files = append $files (printf "/var/run/permguard/join/%s-$(POD_INDEX)" $name) }}{{ end }}{{ join "," $files | quote }}
      - name: PERMGUARD_HOST_JOIN_PIN_FINGERPRINT
        value: {{ .pinFingerprint | quote }}
      - name: PERMGUARD_HOST_JOIN_NAME
        value: {{ printf "%s-$(POD_INDEX)" (.namePrefix | default $g.name) | quote }}
      - name: PERMGUARD_HOST_JOIN_GROUPS
        value: {{ join "," (.groups | default (list $g.name)) | quote }}
      {{- end }}
      {{- end }}
      {{- if .recover }}
      # A recovery drain (TD-2): stop once started, and print the receipt of a complete drain.
      - name: PERMGUARD_SHUTDOWN_RECOVER_DRAIN
        value: "true"
      {{- end }}
      {{- with $g.extraEnv }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
    lifecycle:
      preStop:
        exec:
          command: ["/usr/local/bin/permguard", "drain"]
    securityContext:
      {{- toYaml $root.Values.securityContext | nindent 6 }}
    ports:
      - name: http
        containerPort: {{ $dp.ports.http }}
        protocol: TCP
      {{- if ne (int $dp.ports.grpc) (int $dp.ports.http) }}
      - name: grpc
        containerPort: {{ $dp.ports.grpc }}
        protocol: TCP
      {{- end }}
      - name: telemetry
        containerPort: {{ $dp.ports.telemetry }}
        protocol: TCP
      {{- if $dp.hostListener.enabled }}
      - name: host
        containerPort: {{ $dp.hostListener.port }}
        protocol: TCP
      {{- end }}
    {{- include "permguard.probes" (dict "root" $root) | nindent 4 }}
    resources:
      {{- toYaml $g.resources | nindent 6 }}
    volumeMounts:
      - name: config
        mountPath: /etc/permguard
        readOnly: true
      - name: state
        mountPath: /var/lib/permguard
      - name: tmp
        mountPath: /tmp
      {{- if $dp.tls.secretName }}
      - name: public-tls
        mountPath: /etc/permguard-tls
        readOnly: true
      {{- end }}
      {{- if $dp.hostListener.enabled }}
      - name: host-tls
        mountPath: /etc/permguard-host-tls
        readOnly: true
      {{- end }}
      {{- if and $g.join (not .recover) }}
      - name: join
        mountPath: /var/run/permguard/join
        readOnly: true
      {{- end }}
      {{- if $provisions }}
      - name: identity
        mountPath: /etc/permguard-identity
        readOnly: true
      {{- end }}
      {{- with $dp.extraVolumeMounts }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
volumes:
  {{- with include "permguard.verifyImageVolume" $root | trim }}{{ . | nindent 2 }}{{- end }}
  - name: config
    configMap:
      name: {{ $g.base }}
  - name: tmp
    emptyDir: {}
  {{- if .claim }}
  - name: state
    persistentVolumeClaim:
      claimName: {{ .claim }}
  {{- else if not $stateful }}
  - name: state
    emptyDir: {}
  {{- end }}
  {{- if $dp.tls.secretName }}
  - name: public-tls
    secret:
      secretName: {{ $dp.tls.secretName }}
  {{- end }}
  {{- if $dp.hostListener.enabled }}
  - name: host-tls
    secret:
      secretName: {{ $dp.hostListener.tls.secretName }}
  {{- end }}
  {{- if and $g.join (not .recover) }}
  # The invitations, readable by the server's group only (fsGroup), never by every user: 0440,
  # written in decimal so every YAML reader reads the same mode.
  - name: join
    secret:
      secretName: {{ $g.join.secret }}
      defaultMode: 288
      # A replica that joined never reads its invitations again: the Secret may then be removed.
      optional: true
  {{- end }}
  {{- if $provisions }}
  # The replicas' witnesses, `witness-<ordinal>`: optional, since none is recorded before the
  # first replica printed its own.
  - name: identity
    configMap:
      name: {{ $g.base }}-identity
      optional: true
  {{- end }}
  {{- with $dp.extraVolumes }}
  {{- toYaml . | nindent 2 }}
  {{- end }}
{{- with $g.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $g.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with $g.topologySpreadConstraints }}
topologySpreadConstraints:
  {{- toYaml . | nindent 2 }}
{{- end }}
affinity:
  {{- if $g.affinity }}
  {{- toYaml $g.affinity | nindent 2 }}
  {{- else }}
  # Spread the group's replicas across nodes when the cluster can, rather than requiring it.
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              {{- include "permguard.groupSelectorLabels" (dict "root" $root "group" $g) | nindent 14 }}
  {{- end }}
{{- if .recover }}
restartPolicy: Never
{{- end }}
{{- end -}}
