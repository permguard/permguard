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
	"encoding/json"
	"errors"

	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
	azfiles "github.com/permguard/permguard/pkg/extensions/files"
)

// Permission options.

type PermissionsEngineOptions struct {
	enableVirtualState       bool
	virtualStateViewCombined bool
}

type PermissionsEngineOption func(permEngineSetting *PermissionsEngineOptions) error

func buildPermissionsEngineOptions(options ...PermissionsEngineOption) (*PermissionsEngineOptions, error) {
	permEngineSettings := PermissionsEngineOptions{
		enableVirtualState:       true,
		virtualStateViewCombined: true,
	}
	for _, option := range options {
		err := option(&permEngineSettings)
		if err != nil {
			return nil, err
		}
	}
	return &permEngineSettings, nil
}

func WithPermissionsEngineVirtualState(enableVirtualState bool) PermissionsEngineOption {
	return func(options *PermissionsEngineOptions) error {
		options.enableVirtualState = enableVirtualState
		return nil
	}
}

func WithPermissionsEngineVirtualStateViewCombined(combined bool) PermissionsEngineOption {
	return func(options *PermissionsEngineOptions) error {
		options.virtualStateViewCombined = combined
		return nil
	}
}

// Permissions permit identities to access a resource or execute a specific action and they are granted through the association of policies.
// REF: https://www.permguard.com/docs/access-management/policies/.

type PermissionsEngine struct {
	syntaxVersion    azpolicies.PolicyVersionString
	permissionsState *PermissionsState
}

func NewPermissionsEngine() (*PermissionsEngine, error) {
	permission, err := newPermissionsState()
	if err != nil {
		return nil, err
	}
	permEngine := &PermissionsEngine{
		syntaxVersion:    azpolicies.PolicyLatest,
		permissionsState: permission,
	}
	return permEngine, nil
}

func (e *PermissionsEngine) RegisterPolicy(bData []byte) (bool, error) {
	if bData == nil {
		return false, azfiles.ErrFilesJSONDataMarshaling
	}
	var err error
	var isValid bool
	policy := azpolicies.Policy{}
	err = json.Unmarshal(bData, &policy)
	if err != nil {
		return false, errors.Join(azpolicies.ErrPoliciesInvalidDataType, err)
	}
	if !policy.SyntaxVersion.IsValid() {
		return false, errors.Join(azpolicies.ErrPoliciesUnsupportedVersion, err)
	}
	switch policy.Type {
	case azpolicies.PolicyACType:
		isValid, err = azfiles.IsValidJSON(azpolicies.ACPolicySchema, bData)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, azfiles.ErrFilesJSONSchemaValidation
		}
		acPolicy := azpolicies.ACPolicy{}
		err = json.Unmarshal(bData, &acPolicy)
		if err != nil {
			return false, errors.Join(azfiles.ErrFilesJSONDataMarshaling, err)
		}
		isValid, err = e.registerACPolicy(&acPolicy)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	default:
		return false, azpolicies.ErrPoliciesUnsupportedDataType
	}
	return true, nil
}

func (e *PermissionsEngine) registerACPolicy(policy *azpolicies.ACPolicy) (bool, error) {
	if policy == nil || policy.Type != azpolicies.PolicyACType {
		return false, azpolicies.ErrPoliciesUnsupportedDataType
	}
	isValid, err := azpolicies.ValidateACPolicy(policy)
	if err != nil {
		return false, err
	}
	if !isValid {
		return false, azpolicies.ErrPoliciesInvalidDataType
	}
	extPermsState, err := newExtendedPermissionsState(e.permissionsState)
	if err != nil {
		return false, err
	}
	if len(policy.Permit) > 0 {
		err := extPermsState.permitACPolicyStatements(policy.Permit)
		if err != nil {
			return false, err
		}
	}
	if len(policy.Forbid) > 0 {
		err := extPermsState.fobidACPolicyStatements(policy.Forbid)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

func (e *PermissionsEngine) BuildPermissions(options ...PermissionsEngineOption) (*PermissionsState, error) {
	permEngineSettings, err := buildPermissionsEngineOptions(options...)
	if err != nil {
		return nil, err
	}
	if permEngineSettings.enableVirtualState {
		virtualizer, err := newPermissionsStateVirtualizer(e.syntaxVersion, e.permissionsState)
		if err != nil {
			return nil, err
		}
		return virtualizer.virtualize(permEngineSettings.virtualStateViewCombined)
	}
	return e.permissionsState.clone()
}
