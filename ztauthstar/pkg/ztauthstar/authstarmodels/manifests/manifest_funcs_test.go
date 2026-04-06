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

package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func newValidManifest() *Manifest {
	return &Manifest{
		Metadata: Metadata{Name: "test-manifest"},
		Runtimes: map[string]Runtime{
			"cedar": {
				Language: Language{Name: "cedar", Version: ">=0.0.0"},
				Engine:   Engine{Name: "permguard", Version: ">=0.0.0", Distribution: "community"},
			},
		},
		ZtasApp: []ZtasApp{
			{
				Partitions: map[string]Partition{
					"/": {Runtime: "cedar", Schema: false},
				},
			},
		},
	}
}

func TestValidateSemverRange(t *testing.T) {
	assert := assert.New(t)

	valid := []string{
		"1.2.3",
		"0.0.0",
		">=1.0.0",
		">=0.0.0",
		">=1.0.0 <2.0.0",
		">=0.1.0 <1.0.0",
	}
	for _, v := range valid {
		assert.True(ValidateSemverRange(v), "expected valid: %q", v)
	}

	invalid := []string{
		"",
		"0.0+",
		"0.0",
		"latest",
		"*",
		"^1.0.0",
		"~1.0.0",
		"1.0",
		">1.0.0",
		"<=1.0.0",
	}
	for _, v := range invalid {
		assert.False(ValidateSemverRange(v), "expected invalid: %q", v)
	}
}

func TestValidateManifestValid(t *testing.T) {
	assert := assert.New(t)
	ok, err := ValidateManifest(newValidManifest())
	assert.NoError(err)
	assert.True(ok)
}

func TestValidateManifestNil(t *testing.T) {
	assert := assert.New(t)
	ok, err := ValidateManifest(nil)
	assert.Error(err)
	assert.False(ok)
}

func TestValidateManifestEmptyName(t *testing.T) {
	assert := assert.New(t)
	m := newValidManifest()
	m.Metadata.Name = "   "
	ok, err := ValidateManifest(m)
	assert.Error(err)
	assert.False(ok)
}

func TestValidateManifestSemverRangeVersions(t *testing.T) {
	assert := assert.New(t)
	for _, ver := range []string{"1.2.3", ">=1.0.0", ">=1.0.0 <2.0.0"} {
		m := newValidManifest()
		r := m.Runtimes["cedar"]
		r.Language.Version = ver
		r.Engine.Version = ver
		m.Runtimes["cedar"] = r
		ok, err := ValidateManifest(m)
		assert.NoError(err, "expected no error for version %q", ver)
		assert.True(ok)
	}
}

func TestValidateManifestInvalidLanguageVersion(t *testing.T) {
	assert := assert.New(t)
	for _, bad := range []string{"0.0+", "latest", "", "0.0"} {
		m := newValidManifest()
		r := m.Runtimes["cedar"]
		r.Language.Version = bad
		m.Runtimes["cedar"] = r
		ok, err := ValidateManifest(m)
		assert.Error(err, "expected error for language version %q", bad)
		assert.False(ok)
	}
}

func TestValidateManifestInvalidEngineVersion(t *testing.T) {
	assert := assert.New(t)
	for _, bad := range []string{"0.0+", "latest", "", "0.0"} {
		m := newValidManifest()
		r := m.Runtimes["cedar"]
		r.Engine.Version = bad
		m.Runtimes["cedar"] = r
		ok, err := ValidateManifest(m)
		assert.Error(err, "expected error for engine version %q", bad)
		assert.False(ok)
	}
}

func TestValidateManifestEmptyBizPolicies(t *testing.T) {
	assert := assert.New(t)
	m := newValidManifest()
	m.ZtasApp = []ZtasApp{}
	ok, err := ValidateManifest(m)
	assert.Error(err)
	assert.False(ok)
}

func TestValidateManifestMissingRootPartition(t *testing.T) {
	assert := assert.New(t)
	m := newValidManifest()
	m.ZtasApp[0].Partitions = map[string]Partition{
		"/custom": {Runtime: "cedar", Schema: false},
	}
	ok, err := ValidateManifest(m)
	assert.Error(err)
	assert.False(ok)
}

func TestValidateManifestUndefinedRuntime(t *testing.T) {
	assert := assert.New(t)
	m := newValidManifest()
	m.ZtasApp[0].Partitions["/"] = Partition{Runtime: "nonexistent-runtime", Schema: false}
	ok, err := ValidateManifest(m)
	assert.Error(err)
	assert.False(ok)
}
