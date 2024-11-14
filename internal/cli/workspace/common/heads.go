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

package common

import (
	azerrors "github.com/permguard/permguard/pkg/core/errors"
)

// HeadInfo represents the head information.
type HeadInfo struct {
	ref string
}

// NewHeadInfo creates a new HeadInfo.
func NewHeadInfo(ref string) (*HeadInfo, error) {
	if len(ref) == 0 {
		return nil, azerrors.WrapSystemError(azerrors.ErrCliInput, "cli: invalid ref")
	}
	return &HeadInfo{
		ref: ref,
	}, nil
}

// GetRef returns the ref.
func (i *HeadInfo) GetRef() string {
	return i.ref
}

// GetRefInfo returns the ref information.
func (i *HeadInfo) GetRefInfo() (*RefInfo, error) {
	return ConvertStringWithRepoIDToRefInfo(i.GetRef())
}
