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

package storage

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/permguard/permguard/pkg/agents/runtime"
)

const (
	ctxStgStorageKey = "STORAGE"
	ctxStgLoggerKey  = "LOGGER"
)

type storageCtxKey struct{}

// Context is the storage context.
type Context struct {
	ctx       context.Context
	parentCtx runtime.Context
}

// NewStorageContext creates a new storage context.
func NewStorageContext(runtimeContext runtime.Context, storage Kind) (*Context, error) {
	newLogger := runtimeContext.Logger().With(zap.String(string("storage"), storage.String()))
	data := map[string]any{ctxStgStorageKey: storage, ctxStgLoggerKey: newLogger}
	ctx := context.WithValue(runtimeContext.Context(), storageCtxKey{}, data)
	return &Context{
		ctx:       ctx,
		parentCtx: runtimeContext,
	}, nil
}

// Context returns the context.
func (s *Context) Context() context.Context {
	return s.ctx
}

// Storage returns the storage.
func (s *Context) Storage() Kind {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgStorageKey].(Kind)
}

// Logger returns the logger.
func (s *Context) Logger() *zap.Logger {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgLoggerKey].(*zap.Logger)
}

// ParentLoggerMessage returns the parent logger message.
func (s *Context) ParentLoggerMessage() string {
	storage := s.Storage().String()
	return fmt.Sprintf("%s[%s]", s.parentCtx.ParentLoggerMessage(), storage)
}

// LogMessage returns a well formatted log message.
func (s *Context) LogMessage(message string) string {
	return fmt.Sprintf("%s: %s", s.ParentLoggerMessage(), message)
}

// HostConfigReader returns the host configuration reader.
func (s *Context) HostConfigReader() (runtime.HostConfigReader, error) {
	return s.parentCtx.HostConfigReader()
}

// ServiceConfigReader returns the service configuration reader.
func (s *Context) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return s.parentCtx.ServiceConfigReader()
}
