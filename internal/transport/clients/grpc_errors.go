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
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
)

// wrapGrpcErr checks for common TLS/plaintext mismatch errors and returns
// a more descriptive message with actionable hints.
func wrapGrpcErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "error reading server preface") {
		return fmt.Errorf("%w (hint: the server may require TLS — use grpcs:// scheme or add --tls-skip-verify for self-signed certificates)", err)
	}
	if strings.Contains(msg, "first record does not look like a TLS handshake") {
		return fmt.Errorf("%w (hint: the server does not appear to have TLS enabled — use grpc:// scheme instead of grpcs://)", err)
	}
	if strings.Contains(msg, "certificate signed by unknown authority") {
		return fmt.Errorf("%w (hint: use --tls-skip-verify to skip certificate verification or --tls-ca-file to provide the CA certificate)", err)
	}
	if strings.Contains(msg, "certificate required") {
		return fmt.Errorf("%w (hint: the server requires a client certificate (mTLS) — use --tls-cert-file and --tls-key-file)", err)
	}
	return err
}

// tlsHintUnaryInterceptor wraps gRPC unary call errors with TLS diagnostic hints.
func tlsHintUnaryInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return wrapGrpcErr(invoker(ctx, method, req, reply, cc, opts...))
	}
}

// tlsHintStreamInterceptor wraps gRPC stream creation errors with TLS diagnostic hints.
func tlsHintStreamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, wrapGrpcErr(err)
		}
		return &wrappedClientStream{ClientStream: stream}, nil
	}
}

// wrappedClientStream wraps a grpc.ClientStream to intercept Recv errors.
type wrappedClientStream struct {
	grpc.ClientStream
}

// RecvMsg wraps the underlying RecvMsg with TLS error hints.
func (w *wrappedClientStream) RecvMsg(m any) error {
	return wrapGrpcErr(w.ClientStream.RecvMsg(m))
}
