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

package copier

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ConvertStructToMap converts a struct to a map[string]any using JSON marshaling.
// It returns an error if the input is nil or if marshaling/unmarshaling fails.
func ConvertStructToMap(obj any) (map[string]any, error) {
	if obj == nil {
		return nil, errors.New("input object cannot be nil")
	}
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct to JSON: %w", err)
	}
	var data map[string]any
	err = json.Unmarshal(jsonBytes, &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to map: %w", err)
	}
	return data, nil
}

// ConvertMapToStruct converts a map[string]any to a struct using JSON marshaling.
// It returns an error if the target is nil or if marshaling/unmarshaling fails.
func ConvertMapToStruct(obj map[string]any, target any) error {
	if target == nil {
		return errors.New("target object cannot be nil")
	}
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal map to JSON: %w", err)
	}
	if err = json.Unmarshal(jsonBytes, target); err != nil {
		return fmt.Errorf("failed to unmarshal JSON to struct: %w", err)
	}
	return nil
}
