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

package workspace

import (
	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// GetObjects gets the objects.
func (m *WorkspaceManager) getObjectsInfos(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool) ([]azlangobjs.ObjectInfo, error) {
	filteredObjects := []azlangobjs.ObjectInfo{}
	objects, err := m.cospMgr.GetObjects(includeStorage, includeCode)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return filteredObjects, nil
	}

	objMgr, err := azlangobjs.NewObjectManager()
	if err != nil {
		return nil, err
	}

	for _, object := range objects {
		objInfo, err := objMgr.GetObjectInfo(&object)
		if err != nil {
			return nil, err
		}
		if objInfo.GetType() == azlangobjs.ObjectTypeCommit && !filterCommits {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeTree && !filterTrees {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeBlob && !filterBlob {
			continue
		}
		filteredObjects = append(filteredObjects, *objInfo)
	}
	return filteredObjects, nil
}
