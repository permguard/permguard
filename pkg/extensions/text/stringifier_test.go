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
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestStringify(t *testing.T) {
	assert := assert.New(t)

	tests := map[string]struct {
		Cons func() (string, error)
		Want string
	}{
		"EmptyMap": {
			func() (string, error) {
				instance := make(map[string]any)
				return Stringify(instance, nil)
			},
			"",
		},
		"MapWithIntegers": {
			func() (string, error) {
				instance := make(map[string]any)
				instance["A"] = int(1)
				instance["B"] = int(2)
				return Stringify(instance, nil)
			},
			"#A#1#B#2",
		},
		"MapWithArrays": {
			func() (string, error) {
				instance := make(map[string]any)
				instance["A"] = []string{"A1", "A2", "A3"}
				instance["B"] = []string{"B1", "B2", "A3"}
				return Stringify(instance, nil)
			},
			"#A##A1#A2#A3#B##A3#B1#B2",
		},
		"MapWithArraysAndIgnoreList": {
			func() (string, error) {
				instance := make(map[string]any)
				instance["A"] = []string{"A1", "A2", "A3"}
				instance["B"] = []string{"B1", "B2", "A3"}
				return Stringify(instance, []string{"A"})
			},
			"#B##A3#B1#B2",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, _ := test.Cons()
			assert.Equal(got, test.Want, "wrong result\ngot: %swant: %s", spew.Sdump(got), spew.Sdump(test.Want))
		})
	}
}

func TestMiscellaneousStringsNotValid(t *testing.T) {
	assert := assert.New(t)
	var err error
	{
		_, err = Stringify(make(chan int), nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
	{
		_, err = Stringify("Not a valid Json", nil)
		assert.NotNil(err, "wrong result\ngot: %sshouldn't be nil", spew.Sdump(err))
	}
}
