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

package cosp


const (
	// CodeFileTypePermCode represents the code file type.
	CodeFileTypePermCode = "permcode"
	// CodeFileTypePermSchema represents the schema file type.
	CodeFilePermSchema = "permschema"
	// CodeObjectStateModify represents the modify state.
	CodeObjectStateUnchanged = "unchanged"
	// CodeObjectStateCreate represents the create state.
	CodeObjectStateCreate = "create"
	// CodeObjectStateModify represents the modify state.
	CodeObjectStateModify = "modify"
	// CodeObjectStateDelete represents the delete state.
	CodeObjectStateDelete = "delete"
)

// codeStateConfig represents the config of the code state.
type codeStateConfig struct {
	TreeID string `toml:"treeid"`
}

// codeLocalConfig represents the configuration for the code local.
type codeLocalConfig struct {
	Language  string          `toml:"language"`
	CodeState codeStateConfig `toml:"codestate"`
}

// CodeFile represents the code file.
type CodeFile struct {
	Type         string `json:"type"`
	Path         string `json:"path"`
	OID          string `json:"oid"`
	OType        string `json:"otype"`
	OName        string `json:"oname"`
	CodeID	   	 string `json:"codeid"`
	CodeType	 string `json:"codetype"`
	Mode         uint32 `json:"mode"`
	Section      int    `json:"section"`
	HasErrors    bool   `json:"has_errors"`
	ErrorMessage string `json:"error_message"`
}

// ConvertCodeFilesToPath converts code files to paths.
func ConvertCodeFilesToPath(files []CodeFile) []string {
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = file.Path
	}
	return paths
}

// CodeObject represents the code object.
type CodeObject struct {
	OName 		string `json:"oname"`
	OType 		string `json:"otype"`
	OID			string `json:"oid"`
	CodeID 	 	string `json:"codeid"`
	CodeType 	string `json:"codetype"`
}

// CodeObjectState represents the code object state.
type CodeObjectState struct {
	CodeObject
	State string `json:"state"`
}
