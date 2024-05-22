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

resource "permguard_ac_policy" "person-base-reader" {
    name = "person-base-reader"
    permit = [ "hr-timesheet-writer-any" ]
    forbid = [ "hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" ]
}

resource "permguard_ac_policy_statement" "hr-timesheet-writer-any" {
  name = "permit-hr:timesheet:writer:any"

  actions = [
      "person:ReadTimesheet",
      "person:CreateTimesheet",
      "person:UpdateTimesheet",
      "person:DeleteTimesheet"
  ]
  resources = [
      "uur:581616507495:default:hr-app:organisation:person/*"
  ],
	condition = "DateGreaterThan({{.PermGuard.TokenIssueTime}})' && DateLessThan('{{.PermGuard.CurrentTime}}': '2023-12-31T23:59:59Z')"
}

resource "permguard_ac_policy_statement" "hr-timesheet-writer-bc182146-1598-4fde-99aa-b2d4d08bc1e2" {
  name = "forbid-write-hr:timesheet:writer:bc182146-1598-4fde-99aa-b2d4d08bc1e2"

  actions = [
    "person:Read"
  ]
  resources = [
    "uur:581616507495:default:hr-app:time-management:person/bc182146-1598-4fde-99aa-b2d4d08bc1e2"
  ]
}
