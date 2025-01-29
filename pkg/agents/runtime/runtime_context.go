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

package runtime

import (
	"context"

	"go.uber.org/zap"
)

// RuntimeContext is the interface for the runtime context.
type RuntimeContext interface {
	// GetLogger returns the logger.
	GetLogger() *zap.Logger
	// GetParentLoggerMessage returns the parent logger message.
	GetParentLoggerMessage() string
	// GetHostConfigReader returns the host configuration reader.
	GetHostConfigReader() (HostConfigReader, error)
	// GetServiceConfigReader returns the service configuration reader.
	GetServiceConfigReader() (ServiceConfigReader, error)
	// GetContext returns the context.
	GetContext() context.Context
}

// HostConfigReader declares the host configuration reader.
type HostConfigReader interface {
	// GetAppData returns the zone data.
	GetAppData() string
}

// ServiceConfigReader declares the service configuration reader.
type ServiceConfigReader interface {
	// GetValue returns the value for the given key.
	GetValue(key string) (any, error)
}
