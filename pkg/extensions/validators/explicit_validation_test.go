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

package validators

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestIsValidDirForValidDir(t *testing.T) {
	assert := assert.New(t)
	paths := []string{".", "./", "~/", "../../"}
	for _, path := range paths {
		isValid := IsValidPath(path)
		assert.True(isValid, "wrong result\npath %s should be valid", spew.Sdump(path))
	}
}

func TestIsValidDirForInvalidDir(t *testing.T) {
	assert := assert.New(t)
	paths := []string{"", " "}
	for _, path := range paths {
		isValid := IsValidPath(path)
		assert.False(isValid, "wrong result\npath %s should be not valid", spew.Sdump(path))
	}
}

func TestIsValidPortForValidPort(t *testing.T) {
	assert := assert.New(t)
	ports := []int{1, 10, 9090}
	for _, port := range ports {
		isValid := IsValidPort(port)
		assert.True(isValid, "wrong result\nport %s should be valid", spew.Sdump(port))
	}
}

func TestIsValidPortForInvalidPort(t *testing.T) {
	assert := assert.New(t)
	ports := []int{10454545454, 4574979879}
	for _, port := range ports {
		isValid := IsValidPort(port)
		assert.False(isValid, "wrong result\nport %s should be not valid", spew.Sdump(port))
	}
}
