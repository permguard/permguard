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

package policies

import (
	"sort"
)

func sanitizeSlice[K ~string](source []K) []K {
	outputMap := map[K]struct{}{}
	for _, item := range source {
		if _, ok := outputMap[item]; ok {
			continue
		}
		outputMap[item] = struct{}{}
	}
	keys := make([]string, 0)
	for k := range outputMap {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	items := make([]K, len(keys))
	for i, key := range keys {
		items[i] = K(key)
	}
	return items
}

func SanitizeACPolicyStatement(version PolicyVersionString, acPolicyStatement *ACPolicyStatement) error {
	if !version.IsValid() || acPolicyStatement == nil {
		return ErrPoliciesInvalidDataType
	}
	acPolicyStatement.Resources = sanitizeSlice(acPolicyStatement.Resources)
	acPolicyStatement.Actions = sanitizeSlice(acPolicyStatement.Actions)
	return nil
}

func ValidateACPolicyStatement(version PolicyVersionString, acPolicyStatement *ACPolicyStatement) (bool, error) {
	if !version.IsValid() || acPolicyStatement == nil {
		return false, ErrPoliciesInvalidDataType
	}
	var isValid bool
	var err error
	isValid, err = acPolicyStatement.Name.IsValid(version)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	for _, action := range acPolicyStatement.Actions {
		isValid, err = action.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	for _, resource := range acPolicyStatement.Resources {
		isValid, err = resource.IsValid(version)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}
	return true, nil
}

func ValidateACPolicy(policy *ACPolicy) (bool, error) {
	if policy == nil || !policy.SyntaxVersion.IsValid() || policy.Type != PolicyACType {
		return false, nil
	}
	var isValid bool
	var err error
	isValid, err = policy.Name.IsValid(policy.SyntaxVersion)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, nil
	}
	lists := [][]ACPolicyStatement{policy.Permit, policy.Forbid}
	for _, list := range lists {
		for _, acPolicyStatement := range list {
			isValid, err = ValidateACPolicyStatement(policy.SyntaxVersion, &acPolicyStatement)
			if err != nil {
				return false, err
			}
			if !isValid {
				return false, nil
			}
		}
	}
	return true, nil
}
