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
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
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

// grpcShortMethod extracts the RPC name from a full gRPC method path.
// e.g. "/zap.V1ZAPService/CreateZone" → "CreateZone"
func grpcShortMethod(fullMethod string) string {
	if idx := strings.LastIndex(fullMethod, "/"); idx >= 0 {
		return fullMethod[idx+1:]
	}
	return fullMethod
}

// verboseLoggingUnaryInterceptor prints endpoint, method name, and elapsed time when verbose is enabled.
func verboseLoggingUnaryInterceptor(verbose bool, displayEndpoint string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if !verbose {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		short := grpcShortMethod(method)
		color.HiBlack("[verbose] → %s  endpoint=%s\n", short, displayEndpoint)
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		elapsed := time.Since(start).Round(time.Millisecond)
		if err != nil {
			color.HiBlack("[verbose] ✗ %s  %s\n", short, elapsed)
		} else {
			color.HiBlack("[verbose] ✓ %s  %s\n", short, elapsed)
		}
		return err
	}
}

// verboseLoggingStreamInterceptor prints endpoint, method name, and elapsed time for streams when verbose is enabled.
func verboseLoggingStreamInterceptor(verbose bool, displayEndpoint string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if !verbose {
			stream, err := streamer(ctx, desc, cc, method, opts...)
			if err != nil {
				return nil, wrapGrpcErr(err)
			}
			return &wrappedClientStream{ClientStream: stream}, nil
		}
		short := grpcShortMethod(method)
		color.HiBlack("[verbose] → %s (stream)  endpoint=%s\n", short, displayEndpoint)
		start := time.Now()
		stream, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			elapsed := time.Since(start).Round(time.Millisecond)
			color.HiBlack("[verbose] ✗ %s  %s\n", short, elapsed)
			return nil, wrapGrpcErr(err)
		}
		return &verboseClientStream{ClientStream: stream, short: short, start: start}, nil
	}
}

// verboseClientStream wraps a grpc.ClientStream to log TLS errors and stream completion.
type verboseClientStream struct {
	grpc.ClientStream
	short string
	start time.Time
	done  bool
}

// RecvMsg logs stream completion on EOF or failure, then delegates to the underlying stream.
func (w *verboseClientStream) RecvMsg(m any) error {
	err := w.ClientStream.RecvMsg(m)
	if err != nil && !w.done {
		w.done = true
		elapsed := time.Since(w.start).Round(time.Millisecond)
		if err == io.EOF {
			color.HiBlack("[verbose] ✓ %s  %s\n", w.short, elapsed)
		} else {
			color.HiBlack("[verbose] ✗ %s  %s\n", w.short, elapsed)
		}
	}
	return wrapGrpcErr(err)
}
