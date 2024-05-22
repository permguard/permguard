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

package controllers

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	azservices "github.com/permguard/permguard/pkg/agents/services"

	azpermissions "github.com/permguard/permguard/pkg/accesscontrol/permissions"
	azpolicies "github.com/permguard/permguard/pkg/accesscontrol/policies"
)

type PDPLocalController struct {
	ctx   *azservices.ServiceContext
	cache map[string]any
}

type papDoc struct {
	Items []map[string]any `json:"items"`
}

func loadCache(cache *map[string]any, key string, targetKey string, encode bool, data *papDoc) error {
	for _, item := range data.Items {
		key := item[key].(string)
		if !encode {
			(*cache)[key] = item[targetKey]
		} else {
			bytes, err := json.Marshal(item[targetKey])
			if err != nil {
				return errors.Join(azservices.ErrServiceInvalidAppData, err)
			}
			(*cache)[key] = bytes
		}
	}
	return nil
}

func loadCacheFromDisk(cache *map[string]any, appFolder string, key string, targetKey string, encode bool) error {
	files, err := os.ReadDir(appFolder)
	if err != nil {
		return errors.Join(azservices.ErrServiceInvalidAppData, err)
	}
	for _, file := range files {
		fileName := appFolder + file.Name()
		if filepath.Ext(fileName) != ".json" {
			continue
		}
		bArray, _ := os.ReadFile(fileName)
		var data papDoc
		err := json.Unmarshal(bArray, &data)
		if err != nil {
			return errors.Join(azservices.ErrServiceInvalidAppData, err)
		}
		err = loadCache(cache, key, targetKey, encode, &data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *PDPLocalController) Setup() error {
	var err error
	s.cache = make(map[string]any)
	err = loadCacheFromDisk(&s.cache, s.ctx.GetAppData()+"/identities/", "user_uur", "policies", false)
	if err != nil {
		return azservices.ErrServiceInvalidAppData
	}
	err = loadCacheFromDisk(&s.cache, s.ctx.GetAppData()+"/policies/", "policy_uur", "policy_payload", true)
	if err != nil {
		return azservices.ErrServiceInvalidAppData
	}
	return nil
}

func (s *PDPLocalController) GetPermissionsState(identityUUR azpolicies.UURString, settings ...azpermissions.PermissionsEngineOption) (*azpermissions.PermissionsState, error) {
	engine, err := azpermissions.NewPermissionsEngine()
	if err != nil {
		return nil, err
	}
	policies := s.cache[string(identityUUR)]
	if policies != nil {
		for _, policy := range policies.([]any) {
			registered, err := engine.RegisterPolicy(s.cache[policy.(string)].([]byte))
			if err != nil {
				return nil, err
			}
			if !registered {
				return nil, azservices.ErrServiceGeneric
			}
		}
	}
	return engine.BuildPermissions(settings...)
}

func NewPDPLocalController(serviceContext *azservices.ServiceContext) (*PDPLocalController, error) {
	service := PDPLocalController{
		ctx: serviceContext,
	}
	return &service, nil
}
