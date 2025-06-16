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
	ctxSvcServiceKey = "SERVICE"
	ctxSvcLoggerKey  = "LOGGER"
	ctxSvcCfgReader  = "SERVICE-CONFIG"
)

type serviceCtxKey struct{}

// ServiceContext is the service context.
type ServiceContext struct {
	ctx       context.Context
	parentCtx *HostContext
}

// NewServiceContext creates a new service context.
func NewServiceContext(hostContext *HostContext, service ServiceKind, configReader runtime.ServiceConfigReader) (*ServiceContext, error) {
	newLogger := hostContext.Logger().With(zap.String(string("service"), service.String()))
	data := map[string]any{ctxSvcServiceKey: service, ctxSvcLoggerKey: newLogger, ctxSvcCfgReader: configReader}
	ctx := context.WithValue(hostContext.ctx, serviceCtxKey{}, data)
	return &ServiceContext{
		ctx:       ctx,
		parentCtx: hostContext,
	}, nil
}

// Context returns the context.
func (s *ServiceContext) Context() context.Context {
	return s.ctx
}

// Service returns the service.
func (s *ServiceContext) Service() ServiceKind {
	return s.ctx.Value(serviceCtxKey{}).(map[string]any)[ctxSvcServiceKey].(ServiceKind)
}

// Logger returns the logger.
func (s *ServiceContext) Logger() *zap.Logger {
	return s.ctx.Value(serviceCtxKey{}).(map[string]any)[ctxSvcLoggerKey].(*zap.Logger)
}

// ParentLoggerMessage returns the parent logger message.
func (s *ServiceContext) ParentLoggerMessage() string {
	service := s.Service().String()
	return fmt.Sprintf("%s[%s]", s.parentCtx.ParentLoggerMessage(), service)
}

// LogMessage returns a well formatted log message.
func (s *ServiceContext) LogMessage(message string) string {
	return fmt.Sprintf("%s: %s", s.ParentLoggerMessage(), message)
}

// HostConfigReader returns the host configuration reader.
func (s *ServiceContext) HostConfigReader() (runtime.HostConfigReader, error) {
	return s.parentCtx.HostConfigReader()
}

// ServiceConfigReader returns the service configuration reader.
func (s *ServiceContext) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return s.ctx.Value(serviceCtxKey{}).(map[string]any)[ctxSvcCfgReader].(runtime.ServiceConfigReader), nil
}
