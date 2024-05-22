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

package v1

import (
	azpermissions "github.com/permguard/permguard/pkg/accesscontrol/permissions"
	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
)

// mapToACPolicyStatement maps a policy statement to an AC policy statement.
func mapToACPolicyStatement(acPolicyStatement *azpolicies.ACPolicyStatement) (*ACPolicyStatement, error) {
	result := &ACPolicyStatement{
		Name:      string(acPolicyStatement.Name),
		Actions:   make([]string, len(acPolicyStatement.Actions)),
		Resources: make([]string, len(acPolicyStatement.Resources)),
	}
	for i, action := range acPolicyStatement.Actions {
		result.Actions[i] = string(action)
	}
	for i, resource := range acPolicyStatement.Resources {
		result.Resources[i] = string(resource)
	}
	return result, nil
}

// mapToACPolicyStatementWrapper maps a policy statement wrapper to an AC policy statement wrapper.
func mapToACPolicyStatementWrapper(acPolicyStatementWrapper *azpermissions.ACPolicyStatementWrapper) (*ACPolicyStatementWrapper, error) {
	acPolicyStatement, err := mapToACPolicyStatement(&acPolicyStatementWrapper.Statement)
	if err != nil {
		return nil, err
	}
	result := &ACPolicyStatementWrapper{
		Statement:      acPolicyStatement,
		StatmentHashed: acPolicyStatementWrapper.StatmentHashed,
	}
	return result, nil
}

// mapToPermissionsStateResponse maps a permissions state to a permissions state response.
func mapToPermissionsStateResponse(identityUUR string, permState *azpermissions.PermissionsState) (*PermissionsStateResponse, error) {
	var err error
	var forbidList []azpermissions.ACPolicyStatementWrapper
	forbidList, err = permState.GetACForbiddenPermissions()
	if err != nil {
		return nil, err
	}
	var permitList []azpermissions.ACPolicyStatementWrapper
	permitList, err = permState.GetACPermittedPermissions()
	if err != nil {
		return nil, err
	}
	result := &PermissionsStateResponse{
		Identity: &Identity{
			Uur: identityUUR,
		},
		PermissionsState: &PermissionsState{
			Permissions: &ACPermissions{
				Forbid: make([]*ACPolicyStatementWrapper, len(forbidList)),
				Permit: make([]*ACPolicyStatementWrapper, len(permitList)),
			},
		},
	}
	for i, wrapper := range forbidList {
		acPolicyStatementWrapper, err := mapToACPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Forbid[i] = acPolicyStatementWrapper
	}
	for i, wrapper := range permitList {
		acPolicyStatementWrapper, err := mapToACPolicyStatementWrapper(&wrapper)
		if err != nil {
			return nil, err
		}
		result.PermissionsState.Permissions.Permit[i] = acPolicyStatementWrapper
	}
	return result, nil
}
