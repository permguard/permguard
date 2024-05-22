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

package text

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
)

func stringifyObj(obj any, exclude []string) string {
	if reflect.TypeOf(obj).Kind() == reflect.Array || reflect.TypeOf(obj).Kind() == reflect.Slice {
		if array, ok := obj.([]any); ok {
			arrayString := []string{}
			for _, item := range array {
				arrayString = append(arrayString, fmt.Sprintf("#%s", stringifyMap(item, exclude)))
			}
			arrayBuilder := strings.Builder{}
			sort.Strings(arrayString)
			for _, item := range arrayString {
				arrayBuilder.WriteString(item)
			}
			return arrayBuilder.String()
		}
	}
	return fmt.Sprintf("%v", obj)
}

func stringifyMap(obj any, exclude []string) string {
	if objMap, ok := obj.(map[string]any); ok {
		keys := make([]string, 0, len(objMap))
		for key := range objMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder := strings.Builder{}
		for _, key := range keys {
			if slices.Contains(exclude, key) {
				continue
			}
			value := (objMap)[key]
			if value != nil {
				builder.WriteString(fmt.Sprintf("#%s#%s", key, stringifyMap(value, exclude)))
			}
		}
		return builder.String()
	}
	return stringifyObj(obj, exclude)
}

func Stringify(obj any, exclude []string) (string, error) {
	var objMap map[string]any
	dataObj, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(dataObj, &objMap)
	if err != nil {
		return "", err
	}
	return stringifyMap(objMap, exclude), nil
}
