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

import "fmt"

// ServiceConfiguration declares the service configuration.
type ServiceConfiguration struct {
	data map[string]interface{}
}

// NewServiceConfiguration creates a new service configuration.
func NewServiceConfiguration(data map[string]interface{}) (*ServiceConfiguration, error) {
	if data == nil {
		return nil, fmt.Errorf("service: data is nil")
	}
	return &ServiceConfiguration{
		data: data,
	}, nil
}

// GetValue returns the value for the given key.
func (h *ServiceConfiguration) GetValue(key string) (interface{}, error) {
	value, exists := h.data[key]
	if !exists {
		return nil, fmt.Errorf("service: key %s not found in configuration", key)
	}
	return value, nil
}
