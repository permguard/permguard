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

package grpctls

import (
	"context"
	"fmt"
	"io"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/credentials"
)

// newX509Source creates a SPIFFE X.509 source from the Workload API.
func newX509Source(ctx context.Context, socketPath string) (*workloadapi.X509Source, error) {
	var opts []workloadapi.X509SourceOption
	if socketPath != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr("unix://"+socketPath)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("spiffe: failed to create X509 source: %w", err)
	}
	return source, nil
}

// NewSpiffeServerCredentials builds gRPC mTLS server credentials using the SPIFFE Workload API.
// The returned io.Closer must be closed when the server shuts down to release the X509Source.
func NewSpiffeServerCredentials(ctx context.Context, socketPath string) (credentials.TransportCredentials, io.Closer, error) {
	source, err := newX509Source(ctx, socketPath)
	if err != nil {
		return nil, nil, err
	}
	creds := grpccredentials.MTLSServerCredentials(source, source, tlsconfig.AuthorizeAny())
	return creds, source, nil
}

// NewSpiffeClientCredentials builds gRPC mTLS client credentials using the SPIFFE Workload API.
// The returned io.Closer must be closed when the client is done to release the X509Source.
func NewSpiffeClientCredentials(ctx context.Context, socketPath string) (credentials.TransportCredentials, io.Closer, error) {
	source, err := newX509Source(ctx, socketPath)
	if err != nil {
		return nil, nil, err
	}
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeAny())
	return creds, source, nil
}
