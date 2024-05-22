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

package permissions

import (
	"strings"

	"github.com/google/uuid"

	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
	azcopier "github.com/permguard/permguard/pkg/extensions/copier"
)

type permissionsStateVirtualizer struct {
	syntaxVersion   azpolicies.PolicyVersionString
	permissionState *PermissionsState
}

func newPermissionsStateVirtualizer(syntaxVersion azpolicies.PolicyVersionString, permsState *PermissionsState) (*permissionsStateVirtualizer, error) {
	return &permissionsStateVirtualizer{
		syntaxVersion:   syntaxVersion,
		permissionState: permsState,
	}, nil
}

func (v *permissionsStateVirtualizer) splitWrapperByResource(output map[string]ACPolicyStatementWrapper, wrapper *ACPolicyStatementWrapper) error {
	for _, resource := range wrapper.Statement.Resources {
		dest := azpolicies.ACPolicyStatement{}
		err := azcopier.Copy(&dest, &wrapper.Statement)
		if err != nil {
			return err
		}
		dest.Name = azpolicies.PolicyLabelString((strings.Replace(uuid.NewString(), "-", "", -1)))
		if len(dest.Resources) > 1 {
			dest.Resources = []azpolicies.UURString{resource}
		}
		wrapper, err := createACPolicyStatementWrapper(&dest)
		if err != nil {
			return err
		}
		if _, ok := output[wrapper.StatmentHashed]; ok {
			continue
		}
		output[wrapper.StatmentHashed] = *wrapper
	}
	return nil
}

func (v *permissionsStateVirtualizer) splitWrappersByResource(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	output := map[string]ACPolicyStatementWrapper{}
	for _, wrapper := range wrappers {
		if len(wrapper.Statement.Resources) == 0 {
			continue
		}
		err := v.splitWrapperByResource(output, &wrapper)
		if err != nil {
			return nil, err
		}
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) groupWrappersByConditionalUniqeResource(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	cache := map[string]*azpolicies.ACPolicyStatement{}
	for _, wrapper := range wrappers {
		statement := wrapper.Statement
		if len(statement.Resources) > 1 {
			return nil, ErrPermissionsGeneric
		}
		err := azpolicies.SanitizeACPolicyStatement(v.syntaxVersion, &statement)
		if err != nil {
			return nil, err
		}
		// TODO: Conditions need to be hashed as soon as they are supported.
		//	resourceKey := fmt.Sprintf("%s-%s", string(statement.Resources[0]), text.CreateStringHash(statement.Condition))
		resourceKey := string(statement.Resources[0])
		if _, ok := cache[resourceKey]; !ok {
			cache[resourceKey] = &statement
			continue
		}
		cachedStatement := cache[resourceKey]
		cachedStatement.Actions = append(cachedStatement.Actions, statement.Actions...)
		err = azpolicies.SanitizeACPolicyStatement(v.syntaxVersion, cachedStatement)
		if err != nil {
			return nil, err
		}
	}
	output := map[string]ACPolicyStatementWrapper{}
	for _, statement := range cache {
		wrapper, err := createACPolicyStatementWrapper(statement)
		if err != nil {
			return nil, err
		}
		output[wrapper.StatmentHashed] = *wrapper
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) organiseWrappersByViewType(wrappers map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	output := map[string]ACPolicyStatementWrapper{}
	for key := range wrappers {
		wrapper := wrappers[key]
		if len(wrapper.Statement.Resources) > 1 {
			return nil, ErrPermissionsGeneric
		}
		for _, action := range wrapper.Statement.Actions {
			dest := azpolicies.ACPolicyStatement{}
			err := azcopier.Copy(&dest, &wrapper.Statement)
			if err != nil {
				return nil, err
			}
			dest.Name = azpolicies.PolicyLabelString((strings.Replace(uuid.NewString(), "-", "", -1)))
			dest.Actions = []azpolicies.ActionString{action}
			wrapper, err := createACPolicyStatementWrapper(&dest)
			if err != nil {
				return nil, err
			}
			if _, ok := output[wrapper.StatmentHashed]; ok {
				continue
			}
			output[wrapper.StatmentHashed] = *wrapper
		}
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) virualizeACPolicyStatements(wrappers map[string]ACPolicyStatementWrapper, isCombined bool) ([]ACPolicyStatementWrapper, error) {
	var err error
	var outputMap map[string]ACPolicyStatementWrapper
	outputMap, err = v.splitWrappersByResource(wrappers)
	if err != nil {
		return nil, err
	}
	outputMap, err = v.groupWrappersByConditionalUniqeResource(outputMap)
	if err != nil {
		return nil, err
	}
	if !isCombined {
		outputMap, err = v.organiseWrappersByViewType(outputMap)
		if err != nil {
			return nil, err
		}
	}
	output := make([]ACPolicyStatementWrapper, len(outputMap))
	counter := 0
	for key := range outputMap {
		output[counter] = outputMap[key]
		counter++
	}
	return output, nil
}

func (v *permissionsStateVirtualizer) virtualize(isCombined bool) (*PermissionsState, error) {
	newPermState, err := newPermissionsState()
	if err != nil {
		return nil, err
	}
	var fobidItems []ACPolicyStatementWrapper
	fobidItems, err = v.virualizeACPolicyStatements(v.permissionState.permissions.forbid, isCombined)
	if err != nil {
		return nil, err
	}
	extPermsState, err := newExtendedPermissionsState(newPermState)
	if err != nil {
		return nil, err
	}
	for _, fobidItem := range fobidItems {
		err := extPermsState.fobidACPolicyStatements([]azpolicies.ACPolicyStatement{fobidItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	var permitItems []ACPolicyStatementWrapper
	permitItems, err = v.virualizeACPolicyStatements(v.permissionState.permissions.permit, isCombined)
	if err != nil {
		return nil, err
	}
	for _, permitItem := range permitItems {
		err := extPermsState.permitACPolicyStatements([]azpolicies.ACPolicyStatement{permitItem.Statement})
		if err != nil {
			return nil, err
		}
	}
	return newPermState, nil
}
