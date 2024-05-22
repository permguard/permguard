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

package files

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

func CreateFileIfNotExists(path string, name string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		if err != nil {
			return false, err
		}
	}
	filePath := filepath.Join(path, name)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		file, err := os.Create(filePath)
		if err != nil {
			return false, err
		}
		defer file.Close()
		return true, nil
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// UnmarshalJSONYamlFile unmarshals a json or yaml file into a map.
func UnmarshalJSONYamlFile(path string, out interface{}) error {
	bArray, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bArray, out)
	if err == nil {
		return nil
	}
	err = yaml.Unmarshal(bArray, out)
	return err
}
