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

package clients

import (
	"errors"
	"fmt"
	"strings"
)

// parseGrpcEndpoint validates the endpoint has a grpc:// scheme and returns the host:port.
func parseGrpcEndpoint(endpoint string) (string, error) {
	if endpoint == "" {
		return "", errors.New("client: endpoint is required")
	}
	const grpcScheme = "grpc://"
	if !strings.HasPrefix(endpoint, grpcScheme) {
		return "", fmt.Errorf("client: endpoint scheme must be grpc://, got %s", endpoint)
	}
	hostPort := strings.TrimPrefix(endpoint, grpcScheme)
	if hostPort == "" {
		return "", errors.New("client: endpoint host:port is required after grpc://")
	}
	return hostPort, nil
}
