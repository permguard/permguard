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

package mocks

import (
	"context"

	"go.uber.org/zap"

	mock "github.com/stretchr/testify/mock"
	azruntime "github.com/permguard/permguard/pkg/agents/runtime"
)

// RuntimeContextMock is a mock type for the RuntimeContext type.
type RuntimeContextMock struct {
	mock.Mock
}

// GetLogger returns the logger.
func (c *RuntimeContextMock) GetLogger() *zap.Logger {
	ret := c.Called()

	var r0 *zap.Logger
	if rf, ok := ret.Get(0).(func() *zap.Logger); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(*zap.Logger)
	}
	return r0
}

// GetParentLoggerMessage returns the parent logger message.
func (c *RuntimeContextMock) GetParentLoggerMessage() string {
	ret := c.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}
	return r0
}

// GetContext returns the context.
func (c *RuntimeContextMock) GetContext() context.Context {
	ret := c.Called()

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(context.Context)
	}
	return r0
}

// GetHostConfigReader returns the host configuration reader.
func (c *RuntimeContextMock) GetHostConfigReader() (azruntime.HostConfigReader, error) {
	ret := c.Called()

	var r0 azruntime.HostConfigReader
	if rf, ok := ret.Get(0).(func() azruntime.HostConfigReader); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(azruntime.HostConfigReader)
	}
	return r0, ret.Error(1)
}

// GetServiceConfigReader returns the service configuration reader.
func (c *RuntimeContextMock) GetServiceConfigReader() (azruntime.ServiceConfigReader, error) {
	ret := c.Called()

	var r0 azruntime.ServiceConfigReader
	if rf, ok := ret.Get(0).(func() azruntime.ServiceConfigReader); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(azruntime.ServiceConfigReader)
	}
	return r0, ret.Error(1)
}

// mockHostConfig is a mock type for the HostConfigReader type.
type mockHostConfig struct {
	appData string
}

// GetAppData returns the application data.
func (h *mockHostConfig) GetAppData() string {
	return h.appData
}

// mockServiceConfig is a mock type for the ServiceConfigReader type.
type mockServiceConfig struct {
	values map[string]interface{}
}

// GetValue returns the value for the given key.
func (s *mockServiceConfig) GetValue(key string) (interface{}, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return nil, nil
}

// NewRuntimeContextMock creates a new RuntimeContextMock.
func NewRuntimeContextMock() *RuntimeContextMock {
	ctx := &RuntimeContextMock{}
	ctx.On("GetLogger").Return(zap.NewNop())
	ctx.On("GetParentLoggerMessage").Return("")
	ctx.On("GetContext").Return(context.Background())
	ctx.On("GetHostConfigReader").Return(&mockHostConfig{ appData: "." }, nil)
	serviceMap := map[string]interface{}{
		"enable.default.creation": true,
		"data.fetch.maxpagesize": 10000,
	}
	ctx.On("GetServiceConfigReader").Return(&mockServiceConfig{ values: serviceMap}, nil)
	return ctx
}
