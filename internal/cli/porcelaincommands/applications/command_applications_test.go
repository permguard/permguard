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

package applications

import (
	"testing"

	aztestutils "github.com/permguard/permguard/internal/cli/porcelaincommands/testutils"
)

// TestCreateCommandForApplications tests the CreateCommandForApplications function.
func TestCreateCommandForApplications(t *testing.T) {
	args := []string{}
	outputs := []string{"The official Permguard Command Line Interface", "Copyright © 2022 Nitro Agility S.r.l.", "This command manages applications on the remote server."}
	aztestutils.BaseCommandTest(t, CreateCommandForApplications, args, false, outputs)
}
