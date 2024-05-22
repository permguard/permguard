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
	"errors"

	"github.com/xeipuuv/gojsonschema"
)

func IsValidJSON(jsonSchme []byte, json []byte) (bool, error) {
	schemaLoader := gojsonschema.NewBytesLoader(jsonSchme)
	documentLoader := gojsonschema.NewBytesLoader(json)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return false, errors.Join(ErrFilesJSONSchemaValidation, err)
	}
	if result.Valid() {
		return true, nil
	} else {
		return false, nil
	}
}
