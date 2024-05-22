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
	"sort"

	"github.com/google/uuid"

	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
	azcopier "github.com/permguard/permguard/pkg/extensions/copier"
	aztext "github.com/permguard/permguard/pkg/extensions/text"
)

type ACPolicyStatementWrapper struct {
	ID                  uuid.UUID
	Statement           azpolicies.ACPolicyStatement
	StatmentStringified string
	StatmentHashed      string
}

func createACPolicyStatementWrapper(acPolicyStatement *azpolicies.ACPolicyStatement) (*ACPolicyStatementWrapper, error) {
	if acPolicyStatement == nil {
		return nil, azpolicies.ErrPoliciesInvalidDataType
	}
	acPolicyStatementString, err := aztext.Stringify(acPolicyStatement, []string{"Name"})
	if err != nil {
		return nil, err
	}
	acPolicyStatementHash := aztext.CreateStringHash(acPolicyStatementString)
	return &ACPolicyStatementWrapper{
		ID:                  uuid.New(),
		Statement:           *acPolicyStatement,
		StatmentStringified: acPolicyStatementString,
		StatmentHashed:      acPolicyStatementHash,
	}, nil
}

func createACPolicyStatementWrappers(wrappers map[string]ACPolicyStatementWrapper, acPolicyStatements []azpolicies.ACPolicyStatement) error {
	if acPolicyStatements == nil {
		return azpolicies.ErrPoliciesInvalidDataType
	}
	for _, acPolicyStatement := range acPolicyStatements {
		wrapper, err := createACPolicyStatementWrapper(&acPolicyStatement)
		if err != nil {
			return err
		}
		_, exists := wrappers[wrapper.StatmentHashed]
		if exists {
			continue
		}
		wrappers[wrapper.StatmentHashed] = *wrapper
	}
	return nil
}

type ACPermissions struct {
	forbid map[string]ACPolicyStatementWrapper
	permit map[string]ACPolicyStatementWrapper
}

type PermissionsState struct {
	permissions ACPermissions
}

func newPermissionsState() (*PermissionsState, error) {
	return &PermissionsState{
		permissions: ACPermissions{
			forbid: map[string]ACPolicyStatementWrapper{},
			permit: map[string]ACPolicyStatementWrapper{},
		},
	}, nil
}

func (b *PermissionsState) convertACPolicyStatementsMapToArray(source map[string]ACPolicyStatementWrapper) []ACPolicyStatementWrapper {
	if source == nil {
		return []ACPolicyStatementWrapper{}
	}
	keys := make([]string, 0)
	for k := range source {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	items := make([]ACPolicyStatementWrapper, len(source))
	for i, key := range keys {
		items[i] = source[key]
	}
	return items
}

func (b *PermissionsState) cloneACPolicyStatements(acPolicyStatements map[string]ACPolicyStatementWrapper) (map[string]ACPolicyStatementWrapper, error) {
	dest := map[string]ACPolicyStatementWrapper{}
	err := azcopier.Copy(&dest, acPolicyStatements)
	if err != nil {
		return nil, err
	}
	return dest, nil
}

func (b *PermissionsState) clone() (*PermissionsState, error) {
	dest := PermissionsState{}
	err := azcopier.Copy(&dest, b)
	if err != nil {
		return nil, err
	}
	return &dest, nil
}

func (b *PermissionsState) GetACForbiddenPermissions() ([]ACPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACPolicyStatements(b.permissions.forbid)
	if err != nil {
		return nil, err
	}
	return b.convertACPolicyStatementsMapToArray(wrappers), nil
}

func (b *PermissionsState) GetACPermittedPermissions() ([]ACPolicyStatementWrapper, error) {
	wrappers, err := b.cloneACPolicyStatements(b.permissions.permit)
	if err != nil {
		return nil, err
	}
	return b.convertACPolicyStatementsMapToArray(wrappers), nil
}
