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

package cli

import (
	"testing"

	aztestutils "github.com/permguard/permguard/internal/cli/testutils"
)

// TestCreateCommandForConfigAAPSet tests the createCommandForConfigAAPSet function.
func TestCreateCommandForConfigAAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard CLI", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the aap gRPC target."}
	aztestutils.BaseCommandTest(t, createCommandForConfigAAPSet, args, false, outputs)
}

// TestCreateCommandForConfigPAPSet tests the createCommandForConfigPAPSet function.
func TestCreateCommandForConfigPAPSet(t *testing.T) {
	args := []string{"-h"}
	outputs := []string{"The official PermGuard CLI", "Copyright © 2022 Nitro Agility S.r.l.", "This command sets the pap gRPC target."}
	aztestutils.BaseCommandTest(t, createCommandForConfigPAPSet, args, false, outputs)
}
