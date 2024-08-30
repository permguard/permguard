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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
)

// CreateCommandsForWorkspace creates the workspace commands.
func CreateCommandsForWorkspace(deps azcli.CliDependenciesProvider, v *viper.Viper) []*cobra.Command {
	commands := []*cobra.Command{
		CreateCommandForWorkspaceInit(deps, v),
		CreateCommandForWorkspaceRemote(deps, v),
		CreateCommandForWorkspaceRepo(deps, v),
		CreateCommandForWorkspaceClone(deps, v),
		CreateCommandForWorkspaceValidate(deps, v),
		CreateCommandForWorkspaceFetch(deps, v),
		CreateCommandForWorkspaceDiff(deps, v),
		CreateCommandForWorkspacePlan(deps, v),
		CreateCommandForWorkspaceApply(deps, v),
		CreateCommandForWorkspaceDestroy(deps, v),
	}
	return commands
}
