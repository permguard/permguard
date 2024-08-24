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

	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
)

const (
	ctxStgStorageKey = "STORAGE"
	ctxStgLoggerKey  = "LOGGER"
)

type storageCtxKey struct{}

// StorageContext is the storage context.
type StorageContext struct {
	ctx       context.Context
	parentCtx azruntime.RuntimeContext
}

// NewStorageContext creates a new storage context.
func NewStorageContext(runtimeContext azruntime.RuntimeContext, storage StorageKind) (*StorageContext, error) {
	newLogger := runtimeContext.GetLogger().With(zap.String(string("storage"), storage.String()))
	data := map[string]any{ctxStgStorageKey: storage, ctxStgLoggerKey: newLogger}
	ctx := context.WithValue(runtimeContext.GetContext(), storageCtxKey{}, data)
	return &StorageContext{
		ctx:       ctx,
		parentCtx: runtimeContext,
	}, nil
}

// GetContext returns the context.
func (s *StorageContext) GetContext() context.Context {
	return s.ctx
}

// GetStorage returns the storage.
func (s *StorageContext) GetStorage() StorageKind {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgStorageKey].(StorageKind)
}

// GetLogger returns the logger.
func (s *StorageContext) GetLogger() *zap.Logger {
	return s.ctx.Value(storageCtxKey{}).(map[string]any)[ctxStgLoggerKey].(*zap.Logger)
}

// GetParentLoggerMessage returns the parent logger message.
func (s *StorageContext) GetParentLoggerMessage() string {
	storage := s.GetStorage().String()
	return fmt.Sprintf("%s[%s]", s.parentCtx.GetParentLoggerMessage(), storage)
}

// GetLogMessage returns a well formatted log message.
func (s *StorageContext) GetLogMessage(message string) string {
	return fmt.Sprintf("%s: %s", s.GetParentLoggerMessage(), message)
}

// GetHostConfigReader returns the host configuration reader.
func (s *StorageContext) GetHostConfigReader() (azruntime.HostConfigReader, error) {
	return s.parentCtx.GetHostConfigReader()
}

// GetServiceConfigReader returns the service configuration reader.
func (s *StorageContext) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	return s.parentCtx.GetServiceConfigReader()
}
