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

package servers

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OTelProviders holds the OpenTelemetry trace and metric providers.
type OTelProviders struct {
	TracerProvider *sdktrace.TracerProvider
	MeterProvider  *sdkmetric.MeterProvider
}

// initOTelProviders initializes the OpenTelemetry trace and metric providers.
func initOTelProviders(ctx context.Context, serviceName string, config *ServerConfig, logger *zap.Logger) (*OTelProviders, error) {
	if !config.OTelEnabled() {
		return nil, nil
	}

	endpoint := config.OTelEndpoint()
	sampleRate := config.OTelSampleRate()

	logger.Info(fmt.Sprintf("Initializing OpenTelemetry (endpoint: %s, sample-rate: %.2f)", endpoint, sampleRate))

	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("server: failed to create otel grpc connection: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("server: failed to create otel resource: %w", err)
	}

	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("server: failed to create otel trace exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)

	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("server: failed to create otel metric exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("OpenTelemetry initialized successfully")

	return &OTelProviders{
		TracerProvider: tp,
		MeterProvider:  mp,
	}, nil
}

// shutdownOTelProviders shuts down the OpenTelemetry providers.
func shutdownOTelProviders(ctx context.Context, providers *OTelProviders, logger *zap.Logger) {
	if providers == nil {
		return
	}
	logger.Info("Shutting down OpenTelemetry providers")
	if err := providers.TracerProvider.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown OTel tracer provider", zap.Error(err))
	}
	if err := providers.MeterProvider.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown OTel meter provider", zap.Error(err))
	}
}
