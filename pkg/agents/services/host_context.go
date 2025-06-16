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
	ctxHostHostkey   = "HOST"
	ctxHostServerkey = "SERVER"
	ctxHostLoggerkey = "LOGGER"
	ctxHostCfgReader = "HOST-CONFIG"
)

type hostCtxKey struct{}

// HostContext is the host context.
type HostContext struct {
	ctx context.Context
}

// NewHostContext creates a new host context.
func NewHostContext(host HostKind, hostable Hostable, logger *zap.Logger, configReader runtime.HostConfigReader) (*HostContext, error) {
	newLogger := logger.With(zap.String(string("host"), host.String()))
	data := map[string]any{ctxHostHostkey: host, ctxHostServerkey: hostable, ctxHostLoggerkey: newLogger, ctxHostCfgReader: configReader}
	ctx := context.Background()
	ctx = context.WithValue(ctx, hostCtxKey{}, data)
	return &HostContext{
		ctx: ctx,
	}, nil
}

// Context returns the context.
func (h *HostContext) Context() context.Context {
	return h.ctx
}

// Host returns the host.
func (h *HostContext) Host() HostKind {
	return h.ctx.Value(hostCtxKey{}).(map[string]any)[ctxHostHostkey].(HostKind)
}

// Logger returns the logger.
func (h *HostContext) Logger() *zap.Logger {
	return h.ctx.Value(hostCtxKey{}).(map[string]any)[ctxHostLoggerkey].(*zap.Logger)
}

// HostConfigReader returns the host configuration reader.
func (h *HostContext) HostConfigReader() (runtime.HostConfigReader, error) {
	return h.ctx.Value(hostCtxKey{}).(map[string]any)[ctxHostCfgReader].(runtime.HostConfigReader), nil
}

// Shutdown shuts down the service.
func (h *HostContext) Shutdown(ctx context.Context) {
	h.ctx.Value(hostCtxKey{}).(map[string]any)[ctxHostServerkey].(Hostable).Shutdown(ctx)
}

// ParentLoggerMessage returns the parent logger message.
func (h *HostContext) ParentLoggerMessage() string {
	return fmt.Sprintf("[%s]", h.Host().String())
}

// LogMessage returns a well formatted log message.
func (h *HostContext) LogMessage(message string) string {
	return fmt.Sprintf("%s: %s", h.ParentLoggerMessage(), message)
}
