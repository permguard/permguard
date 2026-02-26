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

//nolint:revive // package name is intentional
package runtime

import (
	"context"
	"fmt"
	"reflect"

	"go.uber.org/zap"
)

// Context is the interface for the runtime context.
type Context interface {
	// Logger returns the logger.
	Logger() *zap.Logger
	// ParentLoggerMessage returns the parent logger message.
	ParentLoggerMessage() string
	// HostConfigReader returns the host configuration reader.
	HostConfigReader() (HostConfigReader, error)
	// ServiceConfigReader returns the service configuration reader.
	ServiceConfigReader() (ServiceConfigReader, error)
	// Context returns the context.
	Context() context.Context
}

// HostConfigReader declares the host configuration reader.
type HostConfigReader interface {
	// AppData returns the zone data.
	AppData() string
}

// ServiceConfigReader declares the service configuration reader.
type ServiceConfigReader interface {
	// Value returns the value for the given key.
	Value(key string) (any, error)
}

// GetTypedValue retrieves a value of type T from any value.
func GetTypedValue[T any](getFunc func(string) (any, error), key string) (T, error) {
	value, err := getFunc(key)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("failed to get value for key %q: %w", key, err)
	}

	if typed, ok := value.(T); ok {
		return typed, nil
	}

	var zero T
	switch any(zero).(type) {
	case string:
		switch v := value.(type) {
		case fmt.Stringer:
			return any(v.String()).(T), nil
		case []byte:
			return any(string(v)).(T), nil
		case string:
			return any(v).(T), nil
		}
	case int:
		switch v := value.(type) {
		case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
			return any(int(reflect.ValueOf(v).Int())).(T), nil
		}
	}

	return zero, fmt.Errorf("type mismatch for key %q: value is %T, expected %T", key, value, zero)
}
