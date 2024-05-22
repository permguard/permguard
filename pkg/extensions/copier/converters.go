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
)

// ConvertStructToMap converts a struct to a map.
func ConvertStructToMap(obj interface{}) (map[string]interface{}, error) {
	var data map[string]interface{}
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonBytes, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ConvertMapToStruct converts a map to a struct.
func ConvertMapToStruct(obj map[string]interface{}, target interface{}) error {
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonBytes, target)
	if err != nil {
		return err
	}
	return nil
}
