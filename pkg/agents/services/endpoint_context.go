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

	"go.uber.org/zap"
)

const (
	ctxEndLoggerKey = "LOGGER"
	ctxEndpPortKey  = "PORT"
)

type endpointCtxKey struct{}

// EndpointContext is the endpoint context.
type EndpointContext struct {
	ctx       context.Context
	parentCtx *ServiceContext
}

// NewEndpointContext creates a new endpoint context.
func NewEndpointContext(serviceContext *ServiceContext, port int) (*EndpointContext, error) {
	newLogger := serviceContext.GetLogger().With(zap.Int("port", port))
	data := map[string]any{ctxEndLoggerKey: newLogger, ctxEndpPortKey: port}
	ctx := context.WithValue(serviceContext.ctx, endpointCtxKey{}, data)
	return &EndpointContext{
		ctx:       ctx,
		parentCtx: serviceContext,
	}, nil
}

// GetContext returns the context.
func (e *EndpointContext) GetContext() context.Context {
	return e.ctx
}

// GetLogger returns the logger.
func (e *EndpointContext) GetLogger() *zap.Logger {
	return e.ctx.Value(endpointCtxKey{}).(map[string]any)[ctxEndLoggerKey].(*zap.Logger)
}

// GetPort returns
func (e *EndpointContext) GetPort() int {
	return e.ctx.Value(endpointCtxKey{}).(map[string]any)[ctxEndpPortKey].(int)
}

// GetParentLoggerMessage returns the parent logger message.
func (e *EndpointContext) GetParentLoggerMessage() string {
	port := e.GetPort()
	return fmt.Sprintf("%s[port: %d]", e.parentCtx.GetParentLoggerMessage(), port)
}

// GetLogMessage returns a well formatted log message.
func (e *EndpointContext) GetLogMessage(message string) string {
	return fmt.Sprintf("%s: %s", e.GetParentLoggerMessage(), message)
}
