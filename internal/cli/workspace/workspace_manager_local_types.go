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
	"os"
	"path/filepath"
	"strings"

	azlangobjs "github.com/permguard/permguard-abs-language/pkg/objects"
)

// codeFileInfo represents info about the code file.
type codeFileInfo struct {
	Path 			string
	OID 			string
	OType 			string
	OName 			string
	Mode 			uint32
	Section 		int
	HasErrors		bool
	ErrorMessage 	string
}

// convertCodeFilesToPath converts code files to paths.
func convertCodeFilesToPath(files []codeFileInfo) []string {
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = file.Path
	}
	return paths
}

func getDirectories(path string) []string {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	var directories []string
	for _, part := range parts {
		if part != "" {
			directories = append(directories, part)
		}
	}
	return directories
}

func getFolderInfo(path string) (string, uint32) {
	mode := uint32(0777)
	info, err := os.Stat(path)
	if err == nil {
		mode = uint32(info.Mode())
	}
	name := filepath.Base(path)
	return name, mode
}

func getParentFodlers(path string) (string, string, string) {
	fileName := filepath.Base(path)
	parentPath := filepath.Dir(path)
	parentFolder := filepath.Base(parentPath)
	if parentPath == "." || parentPath == "/" {
		parentPath = ""
	}
	return parentPath, parentFolder, fileName
}

func buildTreeForCodeFile(codefile codeFileInfo, treesMap map[string]*azlangobjs.Tree) {
	path := codefile.Path
	parentPath, _, fileName := getParentFodlers(path)
	tree, ok := treesMap[parentPath]
	if !ok {
		tree = azlangobjs.NewTree()
		treesMap[parentPath] = tree
	}
	treeItem := azlangobjs.NewTreeEntry(codefile.Mode, codefile.OID, codefile.OType, codefile.OName, fileName)
	tree.AddEntry(treeItem)
}

func linkTrees(path string, treesMap map[string]*azlangobjs.Tree) {
	directories := getDirectories(path)
	var parentTree *azlangobjs.Tree
	for i := 1; i < len(directories); i++ {
		currentFullPath := strings.Join(directories[:i], string(filepath.Separator))
		currentTree, ok := treesMap[currentFullPath]
		if !ok {
			currentTree = azlangobjs.NewTree()
			treesMap[currentFullPath] = currentTree
		}
		if parentTree != nil {
			manager, _ := azlangobjs.NewObjectManager()
			obj, _ := manager.CreateTreeObject(currentTree)
			name, mode := getFolderInfo(currentFullPath)
			parentTreeItem := azlangobjs.NewTreeEntry(mode, obj.GetOID(), "tree", name, name)
			parentTree.AddEntry(parentTreeItem)
		}
		parentTree = currentTree
	}
}

func buildTrees(codeFiles []codeFileInfo) ([]azlangobjs.Tree, error) {
	if len(codeFiles) == 0 {
		return []azlangobjs.Tree{}, nil
	}
	treesMap := make(map[string]*azlangobjs.Tree)
	for _, codeFile := range codeFiles {
		linkTrees(codeFile.Path, treesMap)
	}
	for _, codeFile := range codeFiles {
		buildTreeForCodeFile(codeFile, treesMap)
	}
	for path := range treesMap {
		linkTrees(path, treesMap)
	}
	trees := make([]azlangobjs.Tree, len(treesMap))
	i := 0
	for _, tree := range treesMap {
		trees[i] = *tree
		i++
	}
	return trees, nil
}
