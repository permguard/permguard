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

func TestWildcardString(t *testing.T) {
	assert := assert.New(t)
	{
		pattern := "*"
		values := []string{
			"",
			"Hl",
			"Hal",
			"Hla",
			"Hala",
			"Habcl",
			"Habcla",
			"Hlsfasdfasfd",
			"Hsdfsdfaslsfasdfasfd",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "a*/*b"
		var values []string
		values = []string{
			"a*/*b",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
		values = []string{
			"*a*/*b*",
		}
		for _, value := range values {
			assert.False(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "*a*/*b*"
		values := []string{
			"a*/*b",
			"*a*/*b*",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "**"
		values := []string{
			"",
			"*",
			"**",
			"Hl",
			"Hal",
			"Hla",
			"Hala",
			"Habcl",
			"Habcla",
			"Hlsfasdfasfd",
			"Hsdfsdfaslsfasdfasfd",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "H*l*"
		var values []string
		values = []string{
			"Hl",
			"Hal",
			"Hla",
			"Hala",
			"Habcl",
			"Habcla",
			"Hlsfasdfasfd",
			"Hsdfsdfaslsfasdfasfd",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
		values = []string{
			"hl",
			"hal",
			"hla",
			"hala",
			"habcl",
			"habcla",
			"hlsfasdfasfd",
			"hsdfsdfaslsfasdfasfd",
			"Paperino",
		}
		for _, value := range values {
			assert.False(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.False(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "db*/prod-*"
		var values []string
		values = []string{
			"db*/prod-*",
			"db/prod-001",
			"db-pg/prod-001",
			"db-pg/prod-002",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
		values = []string{
			"",
			"db/",
			"db/prod",
			"adb/prod-001",
		}
		for _, value := range values {
			assert.False(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.False(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
	{
		pattern := "db*/prod-*1"
		var values []string
		values = []string{
			"db*/prod-*1",
			"db/prod-001",
			"db-pg/prod-001",
		}
		for _, value := range values {
			assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
		values = []string{
			"",
			"db/",
			"db/prod",
			"adb/prod-001",
			"db-pg/prod-002",
			"db-pg/prod-0012",
		}
		for _, value := range values {
			assert.False(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
			assert.False(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		}
	}
}

func TestWildcardStringCompare(t *testing.T) {
	assert := assert.New(t)
	{
		pattern := "**a**"
		value := "*a*"
		assert.True(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "*a*"
		value := "**a**"
		assert.True(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %swant: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "*a*"
		value := "*b*a**"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.True(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "*b*a**"
		value := "*a*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "hr-*/*"
		value := "hr-app/Create*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.True(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "hr-app/Create*"
		value := "hr-*/*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "hr-*/*"
		value := "hr-app/*Create*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.True(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "hr-app/*Create*"
		value := "hr-*/*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
	}
	{
		pattern := "hr-app/*Create*"
		value := "hr-app/****Create*"
		assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sdon't want: %s", spew.Sdump(pattern), spew.Sdump(value))
		assert.False(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sdon'tshouldn't be greather then: %s", spew.Sdump(value), spew.Sdump(pattern))
		assert.True(WildcardString(pattern).wildcardMatch(value, false), "wrong result\ngot: %sshould match %s", spew.Sdump(value), spew.Sdump(pattern))
		assert.True(WildcardString(pattern).wildcardMatch(value, true), "wrong result\ngot: %sshould match %s", spew.Sdump(value), spew.Sdump(pattern))
	}
}

func TestWildcardStringComparation(t *testing.T) {
	assert := assert.New(t)
	{
		inclusions := [][]string{
			{
				"hr-app:time-management:data-entry:581616507495:person/bc182146-*-4fde-99aa-b2d4d08bc1e2:person:ReadTimesheet",
				"hr-app:time-management:data-entry:581616507495:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2:person:ReadTimesheet",
			},
			{
				"hr-app:time-management:data-entry:*:person/*99aa-b2d4d08bc1e2:person:ReadTimesheet",
				"hr-app:time-management:data-entry:581616507495:person/bc182146-*-*-99aa-b2d4d08bc1e2:person:ReadTimesheet",
			},
			{
				"hr-app:time-*:*:581616507495:person/*:person:ReadTimesheet",
				"hr-app:time-management:data-entry:581616507495:person/*:person:ReadTimesheet",
			},
		}
		for _, inclusion := range inclusions {
			pattern := inclusion[0]
			value := inclusion[1]
			assert.False(WildcardString(pattern).WildcardEqual(value), "wrong result\ngot: %sshould be equal to %s", spew.Sdump(value), spew.Sdump(pattern))
			assert.True(WildcardString(pattern).WildcardInclude(value), "wrong result\ngot: %sshould include to %s", spew.Sdump(value), spew.Sdump(pattern))

			assert.False(WildcardString(value).WildcardEqual(pattern), "wrong result\ngot: %sshould be equal to %s", spew.Sdump(value), spew.Sdump(pattern))
			assert.False(WildcardString(value).WildcardInclude(pattern), "wrong result\ngot: %sshouldn't include to %s", spew.Sdump(value), spew.Sdump(pattern))
		}
	}
}
