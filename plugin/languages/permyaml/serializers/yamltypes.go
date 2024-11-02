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

package serializers

const (
	// PermYAMLLangPackage is the language package name.
	PermYAMLLangPackage = "permyaml"
)

// Permission is the access control permission.
type Permission struct {
	Name string `yaml:"name"`
	Permit []string `yaml:"permit,omitempty"`
	Forbid []string `yaml:"forbid,omitempty"`
}

// Policy is the access control policy.
type Policy struct {
	Name string `yaml:"name"`
	Actions   []string `yaml:"actions"`
	Resources []string	`yaml:"resources"`
}

// DomainAction represents the domain action.
type DomainAction struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// DomainResource represents the domain resource.
type DomainResource struct {
	Name    string   		`yaml:"name"`
	Actions []DomainAction	`yaml:"actions"`
}

// Domain represents the domain.
type Domain struct {
	Name        string				`yaml:"name"`
	Description string     			`yaml:"description"`
	Resources   []DomainResource 	`yaml:"resources"`
}

// Schema represents the schema for the domains.
type Schema struct {
	Domains []Domain `yaml:"domains"`
}
