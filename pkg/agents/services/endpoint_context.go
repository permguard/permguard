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

	"github.com/permguard/permguard/pkg/agents/runtime"
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
	newLogger := serviceContext.Logger().With(zap.Int("port", port))
	data := map[string]any{ctxEndLoggerKey: newLogger, ctxEndpPortKey: port}
	ctx := context.WithValue(serviceContext.ctx, endpointCtxKey{}, data)
	return &EndpointContext{
		ctx:       ctx,
		parentCtx: serviceContext,
	}, nil
}

// Context returns the context.
func (e *EndpointContext) Context() context.Context {
	return e.ctx
}

// Logger returns the logger.
func (e *EndpointContext) Logger() *zap.Logger {
	return e.ctx.Value(endpointCtxKey{}).(map[string]any)[ctxEndLoggerKey].(*zap.Logger)
}

// Port returns
func (e *EndpointContext) Port() int {
	return e.ctx.Value(endpointCtxKey{}).(map[string]any)[ctxEndpPortKey].(int)
}

// ParentLoggerMessage returns the parent logger message.
func (e *EndpointContext) ParentLoggerMessage() string {
	port := e.Port()
	return fmt.Sprintf("%s[port: %d]", e.parentCtx.ParentLoggerMessage(), port)
}

// LogMessage returns a well formatted log message.
func (e *EndpointContext) LogMessage(message string) string {
	return fmt.Sprintf("%s: %s", e.ParentLoggerMessage(), message)
}

// HostConfigReader returns the host configuration reader.
func (e *EndpointContext) HostConfigReader() (runtime.HostConfigReader, error) {
	return e.parentCtx.HostConfigReader()
}

// ServiceConfigReader returns the service configuration reader.
func (e *EndpointContext) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return e.parentCtx.ServiceConfigReader()
}
