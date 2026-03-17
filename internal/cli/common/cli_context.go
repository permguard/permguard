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

package common

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/permguard/permguard/common/pkg/extensions/validators"
	"github.com/permguard/permguard/pkg/cli"
	"github.com/permguard/permguard/pkg/cli/options"
	"github.com/permguard/permguard/pkg/transport/grpctls"
)

// Build information variables.
var (
	Version   string
	BuildTime string
	GitCommit string
)

// CreateContextAndPrinter creates a new cli context and printer.
func CreateContextAndPrinter(deps cli.DependenciesProvider, cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, cli.Printer, error) {
	ctx, err := newCliContext(cmd, v)
	if err != nil {
		return nil, nil, err
	}
	printer, err := deps.CreatePrinter(ctx.IsVerbose(), ctx.Output())
	if err != nil {
		return nil, nil, err
	}
	return ctx, printer, nil
}

// CliCommandContext is the context for the Cli.
type CliCommandContext struct {
	v            *viper.Viper
	workDir      string
	verbose      bool
	output       string
	verboseLines []string
}

// AppendVerboseLine appends a line to the verbose buffer (used in JSON verbose mode).
func (c *CliCommandContext) AppendVerboseLine(line string) {
	c.verboseLines = append(c.verboseLines, line)
}

// DrainVerboseLines returns and clears the verbose buffer.
func (c *CliCommandContext) DrainVerboseLines() []string {
	lines := c.verboseLines
	c.verboseLines = nil
	return lines
}

// VerboseCollector returns a collect function for gRPC verbose interceptors.
// In terminal+verbose mode it prints immediately; in JSON+verbose mode it buffers.
// Returns nil when verbose is disabled.
func (c *CliCommandContext) VerboseCollector() func(string) {
	if c.IsVerboseTerminalOutput() {
		return func(line string) { color.HiBlack("[verbose] %s\n", line) }
	}
	if c.IsVerboseJSONOutput() {
		return c.AppendVerboseLine
	}
	return nil
}

// newCliContext creates a new CliContext.
func newCliContext(cmd *cobra.Command, v *viper.Viper) (*CliCommandContext, error) {
	ctx := &CliCommandContext{
		v: v,
	}
	workDir, err := cmd.Flags().GetString(FlagWorkingDirectory)
	if err != nil {
		return nil, err
	}
	if !validators.IsValidPath(workDir) {
		return nil, fmt.Errorf("cli: %s is an invalid work directory", workDir)
	}
	ctx.workDir = workDir
	output, err := cmd.Flags().GetString(FlagOutput)
	if err != nil {
		return nil, err
	}
	ctx.output = strings.ToUpper(strings.TrimSpace(output))
	if ctx.output != cli.OutputTerminal && ctx.output != cli.OutputJSON {
		return nil, fmt.Errorf("cli: %s is an invalid output", output)
	}
	verbose, err := cmd.Flags().GetBool(FlagVerbose)
	if err != nil {
		return nil, err
	}
	ctx.verbose = verbose
	return ctx, nil
}

// ClientVersion returns the client version.
func (c *CliCommandContext) ClientVersion() (string, map[string]any) {
	if Version == "" {
		Version = "none"
	}
	if BuildTime == "" {
		BuildTime = "unknown"
	}
	if GitCommit == "" {
		GitCommit = "unknown"
	}
	versionMap := map[string]any{
		"version":    Version,
		"build_time": BuildTime,
		"git_commit": GitCommit,
	}
	return Version, versionMap
}

// Viper returns the viper.
func (c *CliCommandContext) Viper() *viper.Viper {
	return c.v
}

// IsVerbose returns true if verbosity is enabled.
func (c *CliCommandContext) IsVerbose() bool {
	return c.verbose
}

// Output returns the output.
func (c *CliCommandContext) Output() string {
	return c.output
}

// IsTerminalOutput returns true if the output is json.
func (c *CliCommandContext) IsTerminalOutput() bool {
	return c.Output() == cli.OutputTerminal
}

// IsNotVerboseTerminalOutput return true if the output is terminal and verbosity is not enabled.
func (c *CliCommandContext) IsNotVerboseTerminalOutput() bool {
	return c.IsTerminalOutput() && !c.IsVerbose()
}

// IsVerboseTerminalOutput returns true if the output is terminal and verbosity is enabled.
func (c *CliCommandContext) IsVerboseTerminalOutput() bool {
	return c.IsTerminalOutput() && c.IsVerbose()
}

// IsJSONOutput returns true if the output is json.
func (c *CliCommandContext) IsJSONOutput() bool {
	return c.Output() == cli.OutputJSON
}

// IsVerboseJSONOutput returns true if the output is json and verbosity is enabled.
func (c *CliCommandContext) IsVerboseJSONOutput() bool {
	return c.IsJSONOutput() && c.IsVerbose()
}

// WorkDir returns the work directory.
func (c *CliCommandContext) WorkDir() string {
	return c.workDir
}

// ZAPEndpoint returns the zap endpoint.
func (c *CliCommandContext) ZAPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixZAP, FlagSuffixZAPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: zap endpoint is not set — use 'permguard config set zap-endpoint grpc://host:port' to configure it")
	}
	return endpoint.(string), nil
}

// PAPEndpoint returns the pap endpoint.
func (c *CliCommandContext) PAPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixPAP, FlagSuffixPAPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: pap endpoint is not set — use 'permguard config set pap-endpoint grpc://host:port' to configure it")
	}
	return endpoint.(string), nil
}

// PDPEndpoint returns the pdp endpoint.
func (c *CliCommandContext) PDPEndpoint() (string, error) {
	endpoint := c.v.Get(options.FlagName(FlagPrefixPDP, FlagSuffixPDPEndpoint))
	if endpoint == nil {
		return "", errors.New("cli: pdp endpoint is not set — use 'permguard config set pdp-endpoint grpc://host:port' to configure it")
	}
	return endpoint.(string), nil
}

// AuthstarMaxObjectSize returns the authstar max object size.
func (c *CliCommandContext) AuthstarMaxObjectSize() (int, error) {
	key := options.FlagName(FlagPrefixAuthstar, FlagSuffixAuthstarMaxObjectSize)
	val := c.v.Get(key)
	if val == nil {
		return 0, errors.New("cli: authstar-max-object-size is not set")
	}
	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("cli: authstar-max-object-size has invalid type %T", val)
	}
}

// NOTPMaxPacketSize returns the notp max packet size.
func (c *CliCommandContext) NOTPMaxPacketSize() (int, error) {
	key := options.FlagName(FlagPrefixNOTP, FlagSuffixNOTPMaxPacketSize)
	val := c.v.Get(key)
	if val == nil {
		return 0, errors.New("cli: notp-max-packet-size is not set")
	}
	switch v := val.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("cli: notp-max-packet-size has invalid type %T", val)
	}
}

// TLSClientConfig returns the TLS client configuration from CLI flags.
func (c *CliCommandContext) TLSClientConfig() *grpctls.ClientConfig {
	return &grpctls.ClientConfig{
		CAFile:           c.v.GetString(options.FlagName(FlagPrefixTLS, FlagSuffixTLSCAFile)),
		CertFile:         c.v.GetString(options.FlagName(FlagPrefixTLS, FlagSuffixTLSCertFile)),
		KeyFile:          c.v.GetString(options.FlagName(FlagPrefixTLS, FlagSuffixTLSKeyFile)),
		SkipVerify:       c.v.GetBool(options.FlagName(FlagPrefixTLS, FlagSuffixTLSSkipVerify)),
		Spiffe:           c.v.GetBool(options.FlagName(FlagPrefixSpiffe, FlagSuffixSpiffeEnabled)),
		SpiffeSocketPath: c.v.GetString(options.FlagName(FlagPrefixSpiffe, FlagSuffixSpiffeEndpoint)),
	}
}
