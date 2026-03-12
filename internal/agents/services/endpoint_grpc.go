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

package services

import (
	"context"
	"runtime/debug"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/permguard/permguard/pkg/agents/services"
)

// serverUnaryInterceptor returns a unary interceptor for logging and panic recovery.
func serverUnaryInterceptor(serviceCtx *services.EndpointContext) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		logger := serviceCtx.Logger()
		defer func() {
			if err := recover(); err != nil {
				logger.Error(serviceCtx.LogMessage("Request generated a panic"),
					zap.Any("panic", err),
					zap.String("stacktrace", string(debug.Stack())))
			}
		}()
		start := time.Now()
		h, err := handler(ctx, req)
		if err != nil {
			logger.Error(serviceCtx.LogMessage("Request failed"),
				zap.String("method", info.FullMethod),
				zap.Duration("duration", time.Since(start)),
				zap.Error(err))
		} else {
			logger.Debug(serviceCtx.LogMessage("Request served"),
				zap.String("method", info.FullMethod),
				zap.Duration("duration", time.Since(start)))
		}
		return h, err
	}
}

// serverStreamInterceptor returns a stream interceptor for logging and panic recovery.
func serverStreamInterceptor(serviceCtx *services.EndpointContext) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		logger := serviceCtx.Logger()
		defer func() {
			if err := recover(); err != nil {
				logger.Error(serviceCtx.LogMessage("Stream request generated a panic"),
					zap.Any("panic", err),
					zap.String("stacktrace", string(debug.Stack())))
			}
		}()
		start := time.Now()
		err := handler(srv, ss)
		if err != nil {
			logger.Error(serviceCtx.LogMessage("Stream request failed"),
				zap.String("method", info.FullMethod),
				zap.Duration("duration", time.Since(start)),
				zap.Error(err))
		} else {
			logger.Debug(serviceCtx.LogMessage("Stream request served"),
				zap.String("method", info.FullMethod),
				zap.Duration("duration", time.Since(start)))
		}
		return err
	}
}

// grpcServerOptions returns gRPC server options with OTel and custom interceptors chained.
func grpcServerOptions(serviceCtx *services.EndpointContext) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(serverUnaryInterceptor(serviceCtx)),
		grpc.ChainStreamInterceptor(serverStreamInterceptor(serviceCtx)),
	}
}
