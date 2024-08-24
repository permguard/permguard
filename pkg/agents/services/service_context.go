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

	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
)

const (
	ctxSvcServiceKey = "SERVICE"
	ctxSvcLoggerKey  = "LOGGER"
)

type serviceCtxKey struct{}

// ServiceContext is the service context.
type ServiceContext struct {
	ctx       context.Context
	parentCtx *HostContext
}

// NewServiceContext creates a new service context.
func NewServiceContext(hostContext *HostContext, service ServiceKind) (*ServiceContext, error) {
	newLogger := hostContext.GetLogger().With(zap.String(string("service"), service.String()))
	data := map[string]any{ctxSvcServiceKey: service, ctxSvcLoggerKey: newLogger}
	ctx := context.WithValue(hostContext.ctx, serviceCtxKey{}, data)
	return &ServiceContext{
		ctx:       ctx,
		parentCtx: hostContext,
	}, nil
}

// GetContext returns the context.
func (s *ServiceContext) GetContext() context.Context {
	return s.ctx
}

// GetService returns the service.
func (s *ServiceContext) GetService() ServiceKind {
	return s.ctx.Value(serviceCtxKey{}).(map[string]any)[ctxSvcServiceKey].(ServiceKind)
}

// GetLogger returns the logger.
func (s *ServiceContext) GetLogger() *zap.Logger {
	return s.ctx.Value(serviceCtxKey{}).(map[string]any)[ctxSvcLoggerKey].(*zap.Logger)
}

// GetParentLoggerMessage returns the parent logger message.
func (s *ServiceContext) GetParentLoggerMessage() string {
	service := s.GetService().String()
	return fmt.Sprintf("%s[%s]", s.parentCtx.GetParentLoggerMessage(), service)
}

// GetLogMessage returns a well formatted log message.
func (s *ServiceContext) GetLogMessage(message string) string {
	return fmt.Sprintf("%s: %s", s.GetParentLoggerMessage(), message)
}

// GetHostConfigReader returns the host configuration reader.
func (s *ServiceContext) GetHostConfigReader() (azruntime.HostConfigReader, error) {
	return s.parentCtx.GetHostConfigReader()
}
