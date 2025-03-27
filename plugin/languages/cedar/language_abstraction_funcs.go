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

package cedar

import (
	"encoding/json"
	"fmt"
	"strings"

	azauthzen "github.com/permguard/permguard-ztauthstar-engine/pkg/authzen"
	azerrors "github.com/permguard/permguard/pkg/core/errors"
	azmodelspdp "github.com/permguard/permguard/pkg/transport/models/pdp"
)

// verifyKey verifies the key.
func verifyKey(key string) (bool, error) {
	key = strings.ToUpper(key)
	if key == azmodelspdp.Permguard {
		return false, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, fmt.Sprintf("[cedar] invalid entity identifier: %s is reserved by permguard and cannot be used", key))
	}
	return true, nil
}

// verifyUIDType verifies the UID type.
func verifyUIDType(uidType string) (bool, error) {
	uidTypeSnz := strings.ToLower(uidType)
	if strings.HasPrefix(uidTypeSnz, "permguard::") {
		return false, azerrors.WrapSystemErrorWithMessage(azerrors.ErrLanguageSyntax, fmt.Sprintf("[cedar] invalid entity identifier: %s is reserved by permguard and cannot be used", uidType))
	}
	return true, nil
}

// verifyUIDTypeFromEntityMap verifies the UID type from the entity map.
func verifyUIDTypeFromEntityMap(entityMap []map[string]any) (bool, error) {
	for _, entity := range entityMap {
		uidType, ok := entity["uid"].(map[string]any)["type"].(string)
		if !ok {
			continue
		}
		if ok, err := verifyUIDType(uidType); !ok {
			return false, err
		}
	}
	return true, nil
}

// createAuthorizationErrors creates authorization errors.
func createAuthorizationErrors(code string, adminMessage, userMessage string) (*azauthzen.AuthorizationError, *azauthzen.AuthorizationError) {
	var adminError, userError *azauthzen.AuthorizationError
	adminError, _ = azauthzen.NewAuthorizationError(code, adminMessage)
	userError, _ = azauthzen.NewAuthorizationError(code, userMessage)
	return adminError, userError
}

// createPermguardSubjectKind creates a Permguard subject kind.
func createPermguardSubjectKind(kind string) (string, error) {
	kind = strings.ToUpper(kind)
	switch kind {
	case azmodelspdp.PermguardUser:
		kind = "Permguard::IAM::User"
	case azmodelspdp.PermguardRoleActor:
		kind = "Permguard::IAM::RoleActor"
	case azmodelspdp.PermguardTwinActor:
		kind = "Permguard::IAM::TwinActor"
	}
	return kind, nil
}

// createEntityAttribJSON creates an entity attribute JSON.
func createEntityAttribJSON(uidType, uid string, attrs map[string]any) (map[string]any, error) {
	uidTypeJSON, err := json.Marshal(uidType)
	if err != nil {
		return nil, err
	}
	uidJSON, err := json.Marshal(uid)
	if err != nil {
		return nil, err
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}

	jsonTxt := `
{
    "uid": {
        "type": %s,
        "id": %s
    },
    "attrs": %s,
    "parents": []
}`
	jsonTxt = fmt.Sprintf(jsonTxt, string(uidTypeJSON), string(uidJSON), string(attrsJSON))

	var jsonMap map[string]any
	if err = json.Unmarshal([]byte(jsonTxt), &jsonMap); err != nil {
		return nil, err
	}

	return jsonMap, nil
}
