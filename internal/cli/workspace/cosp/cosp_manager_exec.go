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

package cosp

import (
	azicliwkspers "github.com/permguard/permguard/internal/cli/workspace/persistence"
)

// ExecInitalize the plans resources.
func (m *COSPManager) ExecInitalize() error {
	_, err := m.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, m.getCodeDir())
	if err != nil {
		return err
	}
	_, err = m.persMgr.CreateDirIfNotExists(azicliwkspers.PermguardDir, m.getObjectsDir())
	return err
}
