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
	"fmt"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
	aziclicommon "github.com/permguard/permguard/internal/cli/common"
)

// ExecObjects manage the object store.
func (m *WorkspaceManager) ExecObjects(includeStorage, includeCode, filterCommits, filterTrees, filterBlob bool, out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access objects in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	objects, err := m.cospMgr.GetObjects(includeStorage, includeCode)
	if err != nil {
		return failedOpErr(nil, err)
	}

	if len(objects) == 0 {
		out(nil, "", "No objects found in the current workspace.", nil, true)
		return output, nil
	}

	objMgr, err := azlangobjs.NewObjectManager()
	if err != nil {
		return failedOpErr(nil, err)
	}

	filteredObjects := make([]*azlangobjs.ObjectInfo, 0)
	for _, object := range objects {
		objInfo, err := objMgr.GetObjectInfo(&object)
		if err != nil {
			return failedOpErr(nil, err)
		}
		if objInfo.GetType() == azlangobjs.ObjectTypeCommit && !filterCommits {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeTree && !filterTrees {
			continue
		} else if objInfo.GetType() == azlangobjs.ObjectTypeBlob && !filterBlob {
			continue
		}
		filteredObjects = append(filteredObjects, objInfo)
	}

	if m.ctx.IsTerminalOutput() {
		out(nil, "", "Your workspace objects:\n", nil, true)
		for _, object := range filteredObjects {
			out(nil, "", fmt.Sprintf("	- %s %s", aziclicommon.IDText(object.GetOID()), aziclicommon.KeywordText(object.GetType())), nil, true)
		}
		out(nil, "", "\n", nil, true)
	} else if m.ctx.IsJSONOutput() {
		output = out(output, "objects", objects, nil, true)
}

	return output, nil
}

// ExecHistory show the history.
func (m *WorkspaceManager) ExecHistory(out aziclicommon.PrinterOutFunc) (map[string]any, error) {
	failedOpErr := func(output map[string]any, err error) (map[string]any, error) {
		out(nil, "", "Failed to access history in the current workspace.", nil, true)
		return output, err
	}
	output := m.ExecPrintContext(nil, out)
	if !m.isWorkspaceDir() {
		return failedOpErr(nil, m.raiseWrongWorkspaceDirError(out))
	}

	fileLock, err := m.tryLock()
	if err != nil {
		return failedOpErr(nil, err)
	}
	defer fileLock.Unlock()

	// TODO: Implement this method

	return output, nil
}
