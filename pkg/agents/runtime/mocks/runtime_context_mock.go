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

	"github.com/permguard/permguard/pkg/agents/runtime"
	mock "github.com/stretchr/testify/mock"
)

// RuntimeContextMock is a mock type for the Context type.
type RuntimeContextMock struct {
	mock.Mock
}

// Logger returns the logger.
func (c *RuntimeContextMock) Logger() *zap.Logger {
	ret := c.Called()

	var r0 *zap.Logger
	if rf, ok := ret.Get(0).(func() *zap.Logger); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(*zap.Logger)
	}
	return r0
}

// ParentLoggerMessage returns the parent logger message.
func (c *RuntimeContextMock) ParentLoggerMessage() string {
	ret := c.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}
	return r0
}

// Context returns the context.
func (c *RuntimeContextMock) Context() context.Context {
	ret := c.Called()

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(context.Context)
	}
	return r0
}

// HostConfigReader returns the host configuration reader.
func (c *RuntimeContextMock) HostConfigReader() (runtime.HostConfigReader, error) {
	ret := c.Called()

	var r0 runtime.HostConfigReader
	if rf, ok := ret.Get(0).(func() runtime.HostConfigReader); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(runtime.HostConfigReader)
	}
	return r0, ret.Error(1)
}

// ServiceConfigReader returns the service configuration reader.
func (c *RuntimeContextMock) ServiceConfigReader() (runtime.ServiceConfigReader, error) {
	ret := c.Called()

	var r0 runtime.ServiceConfigReader
	if rf, ok := ret.Get(0).(func() runtime.ServiceConfigReader); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(runtime.ServiceConfigReader)
	}
	return r0, ret.Error(1)
}

// mockHostConfig is a mock type for the HostConfigReader type.
type mockHostConfig struct {
	appData string
}

// AppData returns the zone data.
func (h *mockHostConfig) AppData() string {
	return h.appData
}

// mockServiceConfig is a mock type for the ServiceConfigReader type.
type mockServiceConfig struct {
	values map[string]any
}

// Value returns the value for the given key.
func (s *mockServiceConfig) Value(key string) (any, error) {
	if v, ok := s.values[key]; ok {
		return v, nil
	}
	return nil, nil
}

// NewRuntimeContextMock creates a new ContextMock.
func NewRuntimeContextMock(hostCfgReader any, svcCfgReader any) *RuntimeContextMock {
	ctx := &RuntimeContextMock{}
	ctx.On("Logger").Return(zap.NewNop())
	ctx.On("ParentLoggerMessage").Return("")
	ctx.On("Context").Return(context.Background())
	if hostCfgReader == nil {
		hostCfgReader = &mockHostConfig{appData: "."}
	}
	ctx.On("HostConfigReader").Return(hostCfgReader, nil)
	if svcCfgReader == nil {
		serviceMap := map[string]any{
			"data-enable-default-creation": true,
			"data-fetch-maxpagesize":       10000,
		}
		svcCfgReader = &mockServiceConfig{values: serviceMap}
	}
	ctx.On("ServiceConfigReader").Return(svcCfgReader, nil)
	return ctx
}
