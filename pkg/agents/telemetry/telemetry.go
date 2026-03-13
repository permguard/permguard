// Copyright 2024 Nitro Agility S.r.l.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package telemetry provides centralized OpenTelemetry instrumentation for PermGuard.
package telemetry

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "permguard"

var (
	once   sync.Once
	tracer trace.Tracer
	meter  metric.Meter

	// PushAdvertiseTotal counts total push advertise requests.
	PushAdvertiseTotal metric.Int64Counter
	// PushTransferTotal counts total push transfer requests.
	PushTransferTotal metric.Int64Counter
	// PushObjectsCount records the number of objects per push transfer.
	PushObjectsCount metric.Int64Histogram
	// PushBytesTotal counts total bytes pushed.
	PushBytesTotal metric.Int64Counter
	// PushConflictsTotal counts total push conflicts detected.
	PushConflictsTotal metric.Int64Counter

	// PullTotal counts total pull requests.
	PullTotal metric.Int64Counter
	// PullObjectsCount records the number of objects per pull.
	PullObjectsCount metric.Int64Histogram
	// PullCommitsCount records the number of commits per pull.
	PullCommitsCount metric.Int64Histogram
	// PullNegotiateTotal counts total pull negotiate requests.
	PullNegotiateTotal metric.Int64Counter

	// TxCreatedTotal counts total transactions created.
	TxCreatedTotal metric.Int64Counter
	// TxCommittedTotal counts total transactions committed.
	TxCommittedTotal metric.Int64Counter
	// TxFailedTotal counts total transactions failed.
	TxFailedTotal metric.Int64Counter

	// CleanupRunsTotal counts total cleanup job runs.
	CleanupRunsTotal metric.Int64Counter
	// CleanupTxCleanedTotal counts total stale transactions cleaned.
	CleanupTxCleanedTotal metric.Int64Counter
	// CleanupObjDeletedTotal counts total objects deleted by cleanup.
	CleanupObjDeletedTotal metric.Int64Counter

	// ZoneCreateTotal counts total zone create requests.
	ZoneCreateTotal metric.Int64Counter
	// ZoneUpdateTotal counts total zone update requests.
	ZoneUpdateTotal metric.Int64Counter
	// ZoneDeleteTotal counts total zone delete requests.
	ZoneDeleteTotal metric.Int64Counter
	// ZoneFetchTotal counts total zone fetch requests.
	ZoneFetchTotal metric.Int64Counter

	// LedgerCreateTotal counts total ledger create requests.
	LedgerCreateTotal metric.Int64Counter
	// LedgerUpdateTotal counts total ledger update requests.
	LedgerUpdateTotal metric.Int64Counter
	// LedgerDeleteTotal counts total ledger delete requests.
	LedgerDeleteTotal metric.Int64Counter
	// LedgerFetchTotal counts total ledger fetch requests.
	LedgerFetchTotal metric.Int64Counter

	// GRPCRequestTotal counts total gRPC requests by method.
	GRPCRequestTotal metric.Int64Counter

	// AuthzCheckTotal counts total authorization check requests.
	AuthzCheckTotal metric.Int64Counter
	// AuthzDecisionTotal counts total authorization decisions.
	AuthzDecisionTotal metric.Int64Counter
	// AuthzEvaluationsCount records the number of evaluations per authorization check.
	AuthzEvaluationsCount metric.Int64Histogram
	// AuthzPolicyLoadTotal counts total policy store loads.
	AuthzPolicyLoadTotal metric.Int64Counter

	// TLSRequestTotal counts gRPC requests by TLS status (tls_enabled, tls_version, client_cert).
	TLSRequestTotal metric.Int64Counter
	// TLSModeInfo reports the configured server TLS mode as a gauge (tls_mode attribute).
	TLSModeInfo metric.Int64UpDownCounter
)

func init() {
	Init()
}

// Init initializes the telemetry instruments.
func Init() {
	once.Do(func() {
		tracer = otel.Tracer(instrumentationName)
		meter = otel.Meter(instrumentationName)

		PushAdvertiseTotal, _ = meter.Int64Counter("permguard.pap.push.advertise.total",
			metric.WithDescription("Total push advertise requests"))
		PushTransferTotal, _ = meter.Int64Counter("permguard.pap.push.transfer.total",
			metric.WithDescription("Total push transfer requests"))
		PushObjectsCount, _ = meter.Int64Histogram("permguard.pap.push.objects.count",
			metric.WithDescription("Number of objects per push transfer"))
		PushBytesTotal, _ = meter.Int64Counter("permguard.pap.push.bytes.total",
			metric.WithDescription("Total bytes pushed"))
		PushConflictsTotal, _ = meter.Int64Counter("permguard.pap.push.conflicts.total",
			metric.WithDescription("Total push conflicts detected"))

		PullTotal, _ = meter.Int64Counter("permguard.pap.pull.total",
			metric.WithDescription("Total pull requests"))
		PullObjectsCount, _ = meter.Int64Histogram("permguard.pap.pull.objects.count",
			metric.WithDescription("Number of objects per pull"))
		PullCommitsCount, _ = meter.Int64Histogram("permguard.pap.pull.commits.count",
			metric.WithDescription("Number of commits per pull"))
		PullNegotiateTotal, _ = meter.Int64Counter("permguard.pap.pull.negotiate.total",
			metric.WithDescription("Total pull negotiate requests"))

		TxCreatedTotal, _ = meter.Int64Counter("permguard.pap.tx.created.total",
			metric.WithDescription("Total transactions created"))
		TxCommittedTotal, _ = meter.Int64Counter("permguard.pap.tx.committed.total",
			metric.WithDescription("Total transactions committed"))
		TxFailedTotal, _ = meter.Int64Counter("permguard.pap.tx.failed.total",
			metric.WithDescription("Total transactions failed"))

		CleanupRunsTotal, _ = meter.Int64Counter("permguard.pap.cleanup.runs.total",
			metric.WithDescription("Total cleanup job runs"))
		CleanupTxCleanedTotal, _ = meter.Int64Counter("permguard.pap.cleanup.tx.cleaned.total",
			metric.WithDescription("Total stale transactions cleaned"))
		CleanupObjDeletedTotal, _ = meter.Int64Counter("permguard.pap.cleanup.objects.deleted.total",
			metric.WithDescription("Total objects deleted by cleanup"))

		ZoneCreateTotal, _ = meter.Int64Counter("permguard.zap.zone.create.total",
			metric.WithDescription("Total zone create requests"))
		ZoneUpdateTotal, _ = meter.Int64Counter("permguard.zap.zone.update.total",
			metric.WithDescription("Total zone update requests"))
		ZoneDeleteTotal, _ = meter.Int64Counter("permguard.zap.zone.delete.total",
			metric.WithDescription("Total zone delete requests"))
		ZoneFetchTotal, _ = meter.Int64Counter("permguard.zap.zone.fetch.total",
			metric.WithDescription("Total zone fetch requests"))

		LedgerCreateTotal, _ = meter.Int64Counter("permguard.pap.ledger.create.total",
			metric.WithDescription("Total ledger create requests"))
		LedgerUpdateTotal, _ = meter.Int64Counter("permguard.pap.ledger.update.total",
			metric.WithDescription("Total ledger update requests"))
		LedgerDeleteTotal, _ = meter.Int64Counter("permguard.pap.ledger.delete.total",
			metric.WithDescription("Total ledger delete requests"))
		LedgerFetchTotal, _ = meter.Int64Counter("permguard.pap.ledger.fetch.total",
			metric.WithDescription("Total ledger fetch requests"))

		GRPCRequestTotal, _ = meter.Int64Counter("permguard.grpc.request.total",
			metric.WithDescription("Total gRPC requests by method"))

		AuthzCheckTotal, _ = meter.Int64Counter("permguard.pdp.authz.check.total",
			metric.WithDescription("Total authorization check requests"))
		AuthzDecisionTotal, _ = meter.Int64Counter("permguard.pdp.authz.decision.total",
			metric.WithDescription("Total authorization decisions"))
		AuthzEvaluationsCount, _ = meter.Int64Histogram("permguard.pdp.authz.evaluations.count",
			metric.WithDescription("Number of evaluations per authorization check"))
		AuthzPolicyLoadTotal, _ = meter.Int64Counter("permguard.pdp.policy.load.total",
			metric.WithDescription("Total policy store loads"))

		TLSRequestTotal, _ = meter.Int64Counter("permguard.grpc.tls.request.total",
			metric.WithDescription("Total gRPC requests by TLS status"))
		TLSModeInfo, _ = meter.Int64UpDownCounter("permguard.server.tls.mode.info",
			metric.WithDescription("Configured server TLS mode (1 = active)"))
	})
}

// Tracer returns the shared tracer.
func Tracer() trace.Tracer {
	return tracer
}

// MethodAttr returns a metric option with a "method" attribute.
func MethodAttr(method string) metric.AddOption {
	return metric.WithAttributes(attribute.String("method", method))
}

// TLSAttrs returns metric attributes for TLS request tracking.
func TLSAttrs(tlsEnabled bool, tlsVersion string, clientCert bool) metric.AddOption {
	return metric.WithAttributes(
		attribute.Bool("tls_enabled", tlsEnabled),
		attribute.String("tls_version", tlsVersion),
		attribute.Bool("client_cert", clientCert),
	)
}

// TLSModeAttr returns a metric option with a "tls_mode" attribute.
func TLSModeAttr(mode string) metric.AddOption {
	return metric.WithAttributes(attribute.String("tls_mode", mode))
}
