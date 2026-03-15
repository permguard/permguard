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

// Package grpctls provides centralized TLS/mTLS configuration for PermGuard gRPC server and clients.
package grpctls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/credentials"
)

// Mode represents the TLS mode for the server.
type Mode string

const (
	// ModeNone disables TLS (plaintext gRPC).
	ModeNone Mode = "none"
	// ModeTLS enables server-side TLS.
	ModeTLS Mode = "tls"
	// ModeMTLS enables mutual TLS requiring client certificates.
	ModeMTLS Mode = "mtls"
	// ModeExternal uses externally provided certificates (SPIRE, Vault, cert-manager).
	ModeExternal Mode = "external"
	// ModeSpiffe enables native SPIFFE-based mTLS via the Workload API.
	ModeSpiffe Mode = "spiffe"
)

// ParseMode parses a string into a TLS Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case string(ModeNone):
		return ModeNone, nil
	case string(ModeTLS):
		return ModeTLS, nil
	case string(ModeMTLS):
		return ModeMTLS, nil
	case string(ModeExternal):
		return ModeExternal, nil
	case string(ModeSpiffe):
		return ModeSpiffe, nil
	default:
		return "", fmt.Errorf("tls: invalid mode %q, must be one of: none, tls, mtls, external, spiffe", s)
	}
}

// ServerConfig holds TLS configuration for the gRPC server.
type ServerConfig struct {
	Mode             Mode
	CertFile         string
	KeyFile          string
	CAFile           string
	AutoCertDir      string
	SpiffeSocketPath string
}

// Validate checks the server TLS configuration for consistency.
func (c *ServerConfig) Validate() error {
	switch c.Mode {
	case ModeNone:
		return nil
	case ModeTLS:
		hasCert := c.CertFile != "" && c.KeyFile != ""
		hasAutoCert := c.AutoCertDir != ""
		if !hasCert && !hasAutoCert {
			return errors.New("tls: mode=tls requires either cert-file+key-file or auto-cert-dir")
		}
		return nil
	case ModeMTLS:
		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("tls: mode=mtls requires cert-file and key-file")
		}
		if c.CAFile == "" {
			return errors.New("tls: mode=mtls requires ca-file for client certificate verification")
		}
		return nil
	case ModeExternal:
		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("tls: mode=external requires cert-file and key-file")
		}
		if c.CAFile == "" {
			return errors.New("tls: mode=external requires ca-file for client certificate verification")
		}
		return nil
	case ModeSpiffe:
		return nil
	default:
		return fmt.Errorf("tls: unsupported mode %q", c.Mode)
	}
}

// NewServerCredentials builds gRPC transport credentials for the server.
func NewServerCredentials(cfg *ServerConfig) (credentials.TransportCredentials, error) {
	if cfg == nil || cfg.Mode == ModeNone {
		return nil, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	certFile := cfg.CertFile
	keyFile := cfg.KeyFile

	if cfg.Mode == ModeTLS && certFile == "" && cfg.AutoCertDir != "" {
		if err := GenerateAutoCert(cfg.AutoCertDir); err != nil {
			return nil, fmt.Errorf("tls: failed to generate auto certificates: %w", err)
		}
		certFile = filepath.Join(cfg.AutoCertDir, "server-cert.pem")
		keyFile = filepath.Join(cfg.AutoCertDir, "server-key.pem")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to load server certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if cfg.Mode == ModeMTLS || cfg.Mode == ModeExternal {
		caPool, poolErr := loadCAPool(cfg.CAFile)
		if poolErr != nil {
			return nil, poolErr
		}
		tlsCfg.ClientCAs = caPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return credentials.NewTLS(tlsCfg), nil
}

// ClientConfig holds TLS configuration for the gRPC client.
type ClientConfig struct {
	CAFile           string
	CertFile         string
	KeyFile          string
	SkipVerify       bool
	Spiffe           bool
	SpiffeSocketPath string
}

// HasTLS returns true if any TLS configuration is set.
func (c *ClientConfig) HasTLS() bool {
	if c == nil {
		return false
	}
	return c.CAFile != "" || c.CertFile != "" || c.SkipVerify || c.Spiffe
}

// NewClientCredentials builds gRPC transport credentials for the client.
// This should only be called when TLS is required (grpcs:// scheme).
// With no explicit config, it uses the system CA pool for certificate verification.
func NewClientCredentials(cfg *ClientConfig) (credentials.TransportCredentials, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg != nil {
		if cfg.SkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}

		if cfg.CAFile != "" {
			caPool, err := loadCAPool(cfg.CAFile)
			if err != nil {
				return nil, err
			}
			tlsCfg.RootCAs = caPool
		}

		if cfg.CertFile != "" && cfg.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("tls: failed to load client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
	}

	return credentials.NewTLS(tlsCfg), nil
}

// GenerateAutoCert generates a self-signed CA and server certificate in the given directory.
func GenerateAutoCert(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("tls: failed to create auto-cert directory: %w", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: failed to generate CA key: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"PermGuard"},
			CommonName:   "PermGuard Auto CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("tls: failed to create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("tls: failed to parse CA certificate: %w", err)
	}

	if err := writePEM(filepath.Join(dir, "ca-cert.pem"), "CERTIFICATE", caCertDER); err != nil {
		return err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("tls: failed to marshal CA key: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "ca-key.pem"), "EC PRIVATE KEY", caKeyDER); err != nil {
		return err
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("tls: failed to generate server key: %w", err)
	}

	srvTemplate := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			Organization: []string{"PermGuard"},
			CommonName:   "PermGuard Server",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost", "permguard"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}

	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("tls: failed to create server certificate: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "server-cert.pem"), "CERTIFICATE", srvCertDER); err != nil {
		return err
	}
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		return fmt.Errorf("tls: failed to marshal server key: %w", err)
	}
	if err := writePEM(filepath.Join(dir, "server-key.pem"), "EC PRIVATE KEY", srvKeyDER); err != nil {
		return err
	}

	return nil
}

// loadCAPool loads a CA certificate pool from a PEM file.
func loadCAPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("tls: failed to read CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tls: failed to parse CA certificates from %s", caFile)
	}
	return pool, nil
}

// writePEM writes DER-encoded data to a PEM file with restricted permissions.
func writePEM(path string, blockType string, data []byte) error {
	block := &pem.Block{Type: blockType, Bytes: data}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return fmt.Errorf("tls: failed to write %s: %w", path, err)
	}
	return nil
}

// newSerial generates a random serial number for X.509 certificates.
func newSerial() *big.Int {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("tls: failed to generate serial number: %v", err))
	}
	return serial
}
