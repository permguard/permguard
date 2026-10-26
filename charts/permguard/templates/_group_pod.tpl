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
{{- if or $stateful .claim }}
# The orchestrator's claim (WP-1.4): every Pod of a replica moves its volume's claim one
# generation forward before the server opens it, so a frame a previous Pod appends after that
# is recognised as a stale writer's. A container restart inside the same Pod keeps the claim:
# the process before it is gone, and its frames are not stale. From `production` a volume is
# served only under a claim. The volume directory is created inside the mount on the first
# Pod, by this container, for the server's user; the kubelet's fsGroup may add the server's own
# group to it, never anybody else.
initContainers:
  - name: claim
    image: {{ include "permguard.image" (dict "root" $root "repository" $dp.repository) }}
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
containers:
  - name: data-plane
    image: {{ include "permguard.image" (dict "root" $root "repository" $dp.repository) }}
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
      {{- with $dp.extraVolumeMounts }}
      {{- toYaml . | nindent 6 }}
      {{- end }}
volumes:
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
