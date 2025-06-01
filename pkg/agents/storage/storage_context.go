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

// StorageContext is the storage context.
type StorageContext struct {
	ctx       context.Context
	parentCtx runtime.RuntimeContext
}

// NewStorageContext creates a new storage context.
func NewStorageContext(runtimeContext runtime.RuntimeContext, storage StorageKind) (*StorageContext, error) {
	newLogger := runtimeContext.Logger().With(zap.String(string("storage"), storage.String()))
	data := map[string]any{ctxStgStorageKey: storage, ctxStgLoggerKey: newLogger}
	ctx := context.WithValue(runtimeContext.Context(), storageCtxKey{}, data)
	return &StorageContext{
		ctx:       ctx,
		parentCtx: runtimeContext,
	}, nil
}

// Context returns the context.
func (s *StorageContext) Context() context.Context {
	return s.ctx
}

// Storage returns the storage.
func (s *StorageContext) Storage() StorageKind {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgStorageKey].(StorageKind)
}

// Logger returns the logger.
func (s *StorageContext) Logger() *zap.Logger {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgLoggerKey].(*zap.Logger)
}

// ParentLoggerMessage returns the parent logger message.
func (s *StorageContext) ParentLoggerMessage() string {
	storage := s.Storage().String()
	return fmt.Sprintf("%s[%s]", s.parentCtx.ParentLoggerMessage(), storage)
}

// LogMessage returns a well formatted log message.
func (s *StorageContext) LogMessage(message string) string {
	return fmt.Sprintf("%s: %s", s.ParentLoggerMessage(), message)
}

// HostConfigReader returns the host configuration reader.
func (s *StorageContext) HostConfigReader() (runtime.HostConfigReader, error) {
	return s.parentCtx.HostConfigReader()
}

// ServiceConfigReader returns the service configuration reader.
func (s *StorageContext) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	return s.parentCtx.ServiceConfigReader()
}
