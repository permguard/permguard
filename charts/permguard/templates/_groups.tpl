{{/*
Copyright (c) 2022 Nitro Agility S.r.l.
SPDX-License-Identifier: Apache-2.0
*/}}

{{/*
The data plane's groups, resolved (TD-1): `{"groups": [...], "legacy": [...]}` as JSON.

Each group is its values merged over `dataPlane.groupDefaults`, the Plane-wide values filled in where
it states nothing, and what the templates and `checks.yaml` need computed once: the object base
name, whether it keeps temporal history, its merged configuration and environment, its tasks.

A merge is written out field by field rather than with `mergeOverwrite`: that one treats `false`, `0`
and `""` in the group as "not stated", so `persistence: { enabled: false }` would silently keep the
default `true` — exactly the value an operator turning a volume off cannot afford to lose.

`legacy` lists the single-group keys the values file states (`replicaCount`, `autoscaling`,
`persistence`, `podDisruptionBudget`, `service`). Empty `groups` translates them into the one group `default`;
beside a non-empty `groups` `checks.yaml` refuses them.
*/}}
{{- define "permguard.dataPlaneGroups" -}}
{{- $root := . -}}
{{- $dp := .Values.dataPlane -}}
{{- $d := $dp.groupDefaults -}}
{{- $legacy := list -}}
{{- range $key := list "replicaCount" "autoscaling" "persistence" "podDisruptionBudget" "service" -}}
{{- if hasKey $dp $key -}}
{{- $legacy = append $legacy $key -}}
{{- end -}}
{{- end -}}
{{- $raw := $dp.groups | default list -}}
{{- if not $raw -}}
{{- $one := dict "name" "default" "selector" "plane/data/*" -}}
{{- if hasKey $dp "replicaCount" }}{{ $_ := set $one "replicas" $dp.replicaCount }}{{ end -}}
{{- if hasKey $dp "autoscaling" }}{{ $_ := set $one "autoscaling" $dp.autoscaling }}{{ end -}}
{{- if hasKey $dp "persistence" }}{{ $_ := set $one "persistence" $dp.persistence }}{{ end -}}
{{- if hasKey $dp "podDisruptionBudget" }}{{ $_ := set $one "podDisruptionBudget" $dp.podDisruptionBudget }}{{ end -}}
{{- if hasKey $dp "service" }}{{ $_ := set $one "service" $dp.service }}{{ end -}}
{{- $raw = list $one -}}
{{- end -}}
{{- $groups := list -}}
{{- range $g := $raw -}}
{{- $g = $g | default dict -}}
{{- $name := toString ($g.name | default "") -}}
{{- $base := printf "%s-data-plane-%s" (include "permguard.fullname" $root) $name -}}
{{- /* Booleans: stated by the group, or the default. */ -}}
{{- $flag := dict -}}
{{- range $path := list (list "persistence" "enabled") (list "autoscaling" "enabled") (list "service" "enabled") (list "podDisruptionBudget" "enabled") -}}
{{- $v := dig (index $path 0) (index $path 1) "<unset>" $g -}}
{{- if eq (toString $v) "<unset>" -}}
{{- $v = dig (index $path 0) (index $path 1) false $d -}}
{{- end -}}
{{- $_ := set $flag (index $path 0) (eq (toString $v) "true") -}}
{{- end -}}
{{- /*
The blueprint writes an autoscaled group as `autoscaling: { minReplicas, maxReplicas }`: stating
either bound turns autoscaling on, unless the group says `enabled: false`.
*/ -}}
{{- if and (not (hasKey ($g.autoscaling | default dict) "enabled")) (or (hasKey ($g.autoscaling | default dict) "minReplicas") (hasKey ($g.autoscaling | default dict) "maxReplicas")) -}}
{{- $_ := set $flag "autoscaling" true -}}
{{- end -}}
{{- $extraConfig := mergeOverwrite (deepCopy ($dp.extraConfig | default dict)) (deepCopy ($g.extraConfig | default dict)) -}}
{{- $extraEnv := concat ($dp.extraEnv | default list) ($g.extraEnv | default list) -}}
{{- /* Temporal history: the events block on, nested under `dataPlane` or flat, as the server reads it. */ -}}
{{- $nested := dig "dataPlane" "events" "enabled" "" $extraConfig -}}
{{- $flat := dig "events" "enabled" "" $extraConfig -}}
{{- $temporal := or (and $nested (ne (toString $nested) "false")) (and $flat (ne (toString $flat) "false")) -}}
{{- $pull := dig "dataPlane" "events" "pull" (dig "events" "pull" dict $extraConfig) $extraConfig | default dict -}}
{{- $persistence := dict
      "enabled" $flag.persistence
      "size" (dig "persistence" "size" "" $g | default $d.persistence.size | default $root.Values.persistence.size)
      "storageClass" (dig "persistence" "storageClass" "" $g | default $d.persistence.storageClass | default $root.Values.persistence.storageClass)
      "accessModes" (dig "persistence" "accessModes" list $g | default $d.persistence.accessModes | default list)
      "whenScaled" (toString (dig "persistence" "retention" "whenScaled" "" $g | default (ternary "Retain" "Delete" (eq (toString (dig "persistence" "retainOnScaleDown" true $g)) "true")) | default $d.persistence.retention.whenScaled))
      "whenDeleted" (toString (dig "persistence" "retention" "whenDeleted" "" $g | default $d.persistence.retention.whenDeleted))
-}}
{{- $autoscaling := dict
      "enabled" $flag.autoscaling
      "minReplicas" (dig "autoscaling" "minReplicas" $d.autoscaling.minReplicas $g)
      "maxReplicas" (dig "autoscaling" "maxReplicas" $d.autoscaling.maxReplicas $g)
      "targetCPUUtilizationPercentage" (dig "autoscaling" "targetCPUUtilizationPercentage" $d.autoscaling.targetCPUUtilizationPercentage $g)
-}}
{{- $assurance := dict
      "profile" (toString (dig "assurance" "profile" $d.assurance.profile $g))
      "addedControls" (dig "assurance" "addedControls" $d.assurance.addedControls $g | default list)
      "custody" (dig "assurance" "custody" $d.assurance.custody $g | default dict)
-}}
{{- $pdb := dict
      "enabled" $flag.podDisruptionBudget
      "budget" (dig "podDisruptionBudget" "budget" $d.podDisruptionBudget.budget $g)
      "value" (dig "podDisruptionBudget" "value" $d.podDisruptionBudget.value $g)
-}}
{{- $service := dict
      "enabled" $flag.service
      "type" (dig "service" "type" $d.service.type $g)
      "annotations" (dig "service" "annotations" $d.service.annotations $g | default dict)
-}}
{{- $shutdown := dict
      "timeoutSeconds" (int (dig "shutdown" "timeoutSeconds" $d.shutdown.timeoutSeconds $g))
      "drainTimeoutSeconds" (int (dig "shutdown" "drainTimeoutSeconds" $d.shutdown.drainTimeoutSeconds $g))
-}}
{{- $network := dict
      "public" (dig "networkPolicy" "public" "from" (dig "networkPolicy" "public" "from" $root.Values.networkPolicy.public.from $d) $g | default list)
      "telemetry" (dig "networkPolicy" "telemetry" "from" (dig "networkPolicy" "telemetry" "from" $root.Values.networkPolicy.telemetry.from $d) $g | default list)
-}}
{{- $resolved := dict
      "name" $name
      "base" $base
      "selector" (toString ($g.selector | default ""))
      "replicas" (int (ternary $g.replicas $d.replicas (hasKey $g "replicas")))
      "autoscaling" $autoscaling
      "service" $service
      "evidence" (toString (dig "evidence" "mode" $d.evidence.mode $g))
      "persistence" $persistence
      "assurance" $assurance
      "podDisruptionBudget" $pdb
      "shutdown" $shutdown
      "tasks" ($g.tasks | default $d.tasks | default list)
      "networkPolicy" $network
      "resources" ($g.resources | default $dp.resources)
      "nodeSelector" ($g.nodeSelector | default $dp.nodeSelector)
      "tolerations" ($g.tolerations | default $dp.tolerations)
      "affinity" ($g.affinity | default $dp.affinity)
      "topologySpreadConstraints" ($g.topologySpreadConstraints | default $dp.topologySpreadConstraints)
      "extraConfig" $extraConfig
      "extraEnv" $extraEnv
      "temporal" (not (empty $temporal))
      "pullMode" (toString (dig "mode" "local" $pull))
      "pullLedgers" (dig "ledgers" list $pull | default list)
-}}
{{- $groups = append $groups $resolved -}}
{{- end -}}
{{- dict "groups" $groups "legacy" $legacy | toJson -}}
{{- end -}}

{{/*
A selector, parsed as the Host parses it (`permguard_core::authz::Selector`): `{"valid", "prefix",
"descendants", "data"}`. A resource is `host`, `plane/<p>`, `plane/<p>/zone/<id>` or
`plane/<p>/zone/<id>/ledger/<id>`, each component 1 to 128 of `A-Z a-z 0-9 - _ . :`; the selector
is one, optionally ending in `/*`. `data` says the resource is under `plane/data`.
*/}}
{{- define "permguard.selector" -}}
{{- $text := toString . -}}
{{- $descendants := hasSuffix "/*" $text -}}
{{- $prefix := trimSuffix "/*" $text -}}
{{- $parts := splitList "/" $prefix -}}
{{- $valid := true -}}
{{- range $parts -}}
{{- if not (regexMatch "^[A-Za-z0-9._:-]{1,128}$" .) -}}
{{- $valid = false -}}
{{- end -}}
{{- end -}}
{{- $n := len $parts -}}
{{- if eq $n 1 -}}
{{- $valid = and $valid (eq (index $parts 0) "host") -}}
{{- else if eq $n 2 -}}
{{- $valid = and $valid (eq (index $parts 0) "plane") -}}
{{- else if eq $n 4 -}}
{{- $valid = and $valid (eq (index $parts 0) "plane") (eq (index $parts 2) "zone") -}}
{{- else if eq $n 6 -}}
{{- $valid = and $valid (eq (index $parts 0) "plane") (eq (index $parts 2) "zone") (eq (index $parts 4) "ledger") -}}
{{- else -}}
{{- $valid = false -}}
{{- end -}}
{{- $data := and $valid (ge $n 2) (eq (index $parts 0) "plane") (eq (index $parts 1) "data") -}}
{{- dict "valid" $valid "prefix" $prefix "descendants" $descendants "data" $data | toJson -}}
{{- end -}}

{{/*
Whether the parsed selector `.selector` contains the resource `.resource`, as `Selector::contains`:
the resource is the prefix, or below it when the selector descends.
*/}}
{{- define "permguard.selectorContains" -}}
{{- if or (eq .selector.prefix .resource) (and .selector.descendants (hasPrefix (printf "%s/" .selector.prefix) .resource)) -}}
true
{{- end -}}
{{- end -}}

{{/*
The membership tasks of a resolved group, as the closed task contract (`host members invite create
--tasks`, version 1): `{"tasks": [...]}` as JSON, in type order.

The defaults: `policy.mirror` always, `decisions.ship` when evidence is recorded, `events.ship` when
the group keeps temporal history, each on the group's selector with the CLI vector's limits. A
stated task of one of those types narrows it; a stated task of another type adds it.
*/}}
{{- define "permguard.groupTasks" -}}
{{- $g := . -}}
{{- $types := dict
      "policy.mirror" (list "coordinator" "member" "policy")
      "decisions.ship" (list "member" "coordinator" "decision")
      "events.ship" (list "member" "coordinator" "event")
      "events.import" (list "coordinator" "member" "")
      "audit.checkpoints" (list "member" "coordinator" "")
      "zone.secrets" (list "coordinator" "member" "")
-}}
{{- $limits := dict "max_body_bytes" 1048576 "max_concurrency" 4 "max_rate_per_minute" 600 "max_batch_records" 1000 "retention_seconds" 86400 -}}
{{- $wanted := list "policy.mirror" -}}
{{- if ne $g.evidence "disabled" }}{{ $wanted = append $wanted "decisions.ship" }}{{ end -}}
{{- if $g.temporal }}{{ $wanted = append $wanted "events.ship" }}{{ end -}}
{{- $byType := dict -}}
{{- range $type := $wanted -}}
{{- $_ := set $byType $type dict -}}
{{- end -}}
{{- range $stated := $g.tasks -}}
{{- $_ := set $byType (toString $stated.type) $stated -}}
{{- end -}}
{{- $out := list -}}
{{- range $type := keys $byType | sortAlpha -}}
{{- $stated := get $byType $type -}}
{{- $shape := get $types $type | default (list "" "" "") -}}
{{- $resourceTypes := $stated.resourceTypes | default (ternary (list) (list (index $shape 2)) (eq (index $shape 2) "")) -}}
{{- $taskLimits := dict -}}
{{- range $key, $value := $limits -}}
{{- $_ := set $taskLimits $key (int64 (dig $key $value ($stated.limits | default dict))) -}}
{{- end -}}
{{- $required := true -}}
{{- if hasKey $stated "required" }}{{ $required = eq (toString $stated.required) "true" }}{{ end -}}
{{- $out = append $out (dict
      "version" 1
      "task_id" (toString ($stated.taskId | default (replace "." "-" $type)))
      "type" $type
      "provider_role" (index $shape 0)
      "consumer_role" (index $shape 1)
      "selector" (toString ($stated.selector | default $g.selector))
      "resource_types" $resourceTypes
      "required" $required
      "limits" $taskLimits
      "assurance_requirements" ($stated.assuranceRequirements | default list)
) -}}
{{- end -}}
{{- dict "tasks" $out | toJson -}}
{{- end -}}

{{/*
The configuration a Host's assurance values render (TD-1): `assurance` and, when custody is stated,
`operations.keys`. Takes the resolved `assurance` dict; answers YAML.
*/}}
{{- define "permguard.assuranceConfig" -}}
{{- $a := . -}}
{{- $assurance := dict "profile" $a.profile -}}
{{- if $a.addedControls }}{{ $_ := set $assurance "added_controls" $a.addedControls }}{{ end -}}
{{- $config := dict "assurance" $assurance -}}
{{- $c := $a.custody | default dict -}}
{{- if $c -}}
{{- $keys := dict -}}
{{- if $c.provider }}{{ $_ := set $keys "custody" (toString $c.provider) }}{{ end -}}
{{- $rings := dict -}}
{{- if $c.identity }}{{ $_ := set $rings "host.identity" (dict "custody" (toString $c.identity)) }}{{ end -}}
{{- if $c.operations }}{{ $_ := set $rings "host.operations" (dict "custody" (toString $c.operations)) }}{{ end -}}
{{- if $rings }}{{ $_ := set $keys "rings" $rings }}{{ end -}}
{{- with $c.pkcs11 -}}
{{- $p := dict -}}
{{- if .module }}{{ $_ := set $p "module" (toString .module) }}{{ end -}}
{{- if .tokenLabel }}{{ $_ := set $p "token_label" (toString .tokenLabel) }}{{ end -}}
{{- if .pinRef }}{{ $_ := set $p "pin_ref" (toString .pinRef) }}{{ end -}}
{{- $_ := set $keys "pkcs11" $p -}}
{{- end -}}
{{- with $c.kms -}}
{{- $k := dict -}}
{{- if .address }}{{ $_ := set $k "address" (toString .address) }}{{ end -}}
{{- if .mount }}{{ $_ := set $k "mount" (toString .mount) }}{{ end -}}
{{- if .tokenRef }}{{ $_ := set $k "token_ref" (toString .tokenRef) }}{{ end -}}
{{- if .ca }}{{ $_ := set $k "ca" (toString .ca) }}{{ end -}}
{{- $_ := set $keys "kms" $k -}}
{{- end -}}
{{- $_ := set $config "operations" (dict "keys" $keys) -}}
{{- end -}}
{{- toYaml $config -}}
{{- end -}}

{{/*
The selector labels of one group: the Plane's, and the group's name.
*/}}
{{- define "permguard.groupSelectorLabels" -}}
{{ include "permguard.selectorLabels" (dict "root" .root "component" "data-plane") }}
permguard.com/group: {{ .group.name }}
{{- end -}}

{{- define "permguard.groupLabels" -}}
{{ include "permguard.componentLabels" (dict "root" .root "component" "data-plane") }}
permguard.com/group: {{ .group.name }}
{{- end -}}

{{/*
The assurance values of the control plane or the all-in-one, resolved as a group's are: `{"profile",
"addedControls", "custody"}` as JSON.
*/}}
{{- define "permguard.planeAssurance" -}}
{{- $a := .assurance | default dict -}}
{{- dict "profile" (toString ($a.profile | default "production")) "addedControls" ($a.addedControls | default list) "custody" ($a.custody | default dict) | toJson -}}
{{- end -}}

{{/*
Every Host this release configures, for the checks a configuration answers whatever its Plane:
`{"units": [{"label", "kind", "extraConfig", "extraEnv", "persists", "assurance", "tls"}]}` as JSON.
`kind` is `controlPlane`, `allInOne` or `dataPlane`; a data plane group's `label` is
`dataPlane.groups[<name>]` and its configuration and environment are the merged ones.
*/}}
{{- define "permguard.configUnits" -}}
{{- $root := . -}}
{{- $units := list -}}
{{- range $kind, $plane := dict "controlPlane" .Values.controlPlane "allInOne" .Values.allInOne -}}
{{- if $plane.enabled -}}
{{- $units = append $units (dict
      "label" $kind
      "enabled" true
      "kind" $kind
      "extraConfig" ($plane.extraConfig | default dict)
      "extraEnv" ($plane.extraEnv | default list)
      "persists" (not (empty (include "permguard.persists" (dict "root" $root "plane" $plane))))
      "assurance" (include "permguard.planeAssurance" $plane | fromJson)
      "tls" $plane.tls
) -}}
{{- end -}}
{{- end -}}
{{- if .Values.dataPlane.enabled -}}
{{- range $g := (include "permguard.dataPlaneGroups" $root | fromJson).groups -}}
{{- $units = append $units (dict
      "label" (printf "dataPlane.groups[%s]" $g.name)
      "enabled" true
      "kind" "dataPlane"
      "extraConfig" $g.extraConfig
      "extraEnv" $g.extraEnv
      "persists" $g.persistence.enabled
      "assurance" $g.assurance
      "tls" $root.Values.dataPlane.tls
      "evidence" $g.evidence
) -}}
{{- end -}}
{{- end -}}
{{- dict "units" $units | toJson -}}
{{- end -}}
