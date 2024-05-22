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
	"fmt"
	"runtime/debug"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	azservices "github.com/permguard/permguard/pkg/agents/services"
)

// withServerUnaryInterceptor returns a grpc.ServerOption that adds a unary interceptor to the server.
func withServerUnaryInterceptor(serviceCtx *azservices.EndpointContext) grpc.ServerOption {
	return grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		logger := serviceCtx.GetLogger()
		defer func() {
			if err := recover(); err != nil {
				logger.Error(serviceCtx.GetLogMessage(fmt.Sprintf("Request generted a panic: %v stacktrace:%s", err, debug.Stack())))
			}
		}()
		start := time.Now()
		h, err := handler(ctx, req)
		if err != nil {
			logger.Error(serviceCtx.GetLogMessage(fmt.Sprintf("Request failed to be served - method:%s duration:%s error:%v", info.FullMethod, time.Since(start), err)), zap.Error(err))
		} else {
			logger.Debug(serviceCtx.GetLogMessage(fmt.Sprintf("Request - method:%s duration:%s", info.FullMethod, time.Since(start))), zap.Duration("duration", time.Since(start)))
		}
		return h, err
	})
}
