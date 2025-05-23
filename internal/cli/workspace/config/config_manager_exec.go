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

package config

import (
	"fmt"
	"strings"

	"github.com/permguard/permguard/internal/cli/common"
	wkscommon "github.com/permguard/permguard/internal/cli/workspace/common"
)

// ExecInitialize initializes the config resources.
func (m *ConfigManager) ExecInitialize() error {
	version, _ := m.ctx.GetClientVersion()
	cfg := config{
		Core: coreConfig{
			ClientVersion: version,
		},
		Remotes: map[string]remoteConfig{},
		Ledgers: map[string]ledgerConfig{},
	}
	return m.saveConfig(false, &cfg)
}

// ExecAddRemote adds a remote.
func (m *ConfigManager) ExecAddRemote(remote string, server string, zap int, pap int, output map[string]any, out common.PrinterOutFunc) (map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	remote, err := wkscommon.SanitizeRemote(remote)
	if err != nil {
		return output, err
	}
	if wkscommon.IsReservedKeyword(remote) {
		return output, fmt.Errorf("cli: remote %s is a reserved keyword", remote)
	}
	server = strings.ToLower(server)
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	for rmt := range cfg.Remotes {
		if remote == rmt {
			return output, fmt.Errorf("cli: remote %s already exists", remote)
		}
	}
	cfgRemote := remoteConfig{
		Server:  server,
		ZAPPort: zap,
		PAPPort: pap,
	}
	cfg.Remotes[remote] = cfgRemote
	m.saveConfig(true, cfg)
	out(nil, "", fmt.Sprintf("Remote %s has been added.", common.KeywordText(remote)), nil, true)
	output = map[string]any{}
	if m.ctx.IsJSONOutput() {
		remotes := []any{}
		remoteObj := map[string]any{
			"remote":     remote,
			"zap_server": cfgRemote.Server,
			"zap_port":   cfgRemote.ZAPPort,
			"pap_server": cfgRemote.Server,
			"pap_port":   cfgRemote.PAPPort,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "remotes", remotes, nil, true)
	}
	return output, nil
}

// ExecRemoveRemote removes a remote.
func (m *ConfigManager) ExecRemoveRemote(remote string, output map[string]any, out common.PrinterOutFunc) (map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	remote, err := wkscommon.SanitizeRemote(remote)
	if err != nil {
		return output, err
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if _, ok := cfg.Remotes[remote]; !ok {
		return output, fmt.Errorf("cli: remote %s does not exist", remote)
	}
	for ledger := range cfg.Ledgers {
		if cfg.Ledgers[ledger].Remote == remote {
			return output, fmt.Errorf("cli: remote %s is used by ledger %s", remote, ledger)
		}
	}
	cfgRemote := cfg.Remotes[remote]
	out(nil, "", fmt.Sprintf("Remote %s has been removed.", common.KeywordText(remote)), nil, true)
	output = map[string]any{}
	if m.ctx.IsJSONOutput() {
		remotes := []any{}
		remoteObj := map[string]any{
			"remote":     remote,
			"zap_server": cfgRemote.Server,
			"zap_port":   cfgRemote.ZAPPort,
			"pap_server": cfgRemote.Server,
			"pap_port":   cfgRemote.PAPPort,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "remotes", remotes, nil, true)
	}
	delete(cfg.Remotes, remote)
	m.saveConfig(true, cfg)
	return output, nil
}

// ExecListRemotes lists the remotes.
func (m *ConfigManager) ExecListRemotes(output map[string]any, out common.PrinterOutFunc) (map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if m.ctx.IsTerminalOutput() {
		remotes := []string{}
		for cfgRemote := range cfg.Remotes {
			remotes = append(remotes, cfgRemote)
		}
		if len(remotes) == 0 {
			out(nil, "", "Your workspace doesn't have any remote configured.", nil, true)
		} else {
			out(nil, "", "Your workspace configured remotes:\n", nil, true)
			for _, remote := range remotes {
				out(nil, "", fmt.Sprintf("	- %s", common.KeywordText(remote)), nil, true)
			}
			out(nil, "", "\n", nil, false)
		}
	} else if m.ctx.IsJSONOutput() {
		remotes := []any{}
		for cfgRemote := range cfg.Remotes {
			remoteObj := map[string]any{
				"remote":     cfgRemote,
				"zap_server": cfg.Remotes[cfgRemote].Server,
				"zap_port":   cfg.Remotes[cfgRemote].ZAPPort,
				"pap_server": cfg.Remotes[cfgRemote].Server,
				"pap_port":   cfg.Remotes[cfgRemote].PAPPort,
			}
			remotes = append(remotes, remoteObj)
		}
		output = out(output, "remotes", remotes, nil, true)
	}
	return output, nil
}

// ExecAddLedger adds a ledger.
func (m *ConfigManager) ExecAddLedger(ledgerURI, ref, remote, ledger, ledgerID string, zoneID int64, output map[string]any, out common.PrinterOutFunc) (map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	var cfgLedger ledgerConfig
	exists := false
	for range cfg.Ledgers {
		if cfg.Ledgers[ledgerURI].Remote == remote {
			cfgLedger = cfg.Ledgers[ledgerURI]
			exists = true
			break
		}
	}
	if !exists {
		for key, ledger := range cfg.Ledgers {
			ledger.IsHead = false
			cfg.Ledgers[key] = ledger
		}
		cfgLedger = ledgerConfig{
			Ref:        ref,
			Remote:     remote,
			ZoneID:     zoneID,
			LedgerName: ledger,
			LedgerID:   ledgerID,
			IsHead:     true,
		}
		cfg.Ledgers[ledgerURI] = cfgLedger
		m.saveConfig(true, cfg)
	}
	if m.ctx.IsVerboseTerminalOutput() {
		out(nil, "ledger", fmt.Sprintf("Ref successfully set to %s.", common.KeywordText(cfgLedger.Ref)), nil, true)
	}
	out(nil, "", fmt.Sprintf("Ledger %s has been added.", common.KeywordText(ledger)), nil, true)
	output = map[string]any{}
	if m.ctx.IsJSONOutput() {
		remotes := []any{}
		remoteObj := map[string]any{
			"ref":        cfgLedger.Ref,
			"ledger_uri": ledgerURI,
			"ledger_id":  cfgLedger.LedgerID,
			"is_head":    cfgLedger.IsHead,
		}
		remotes = append(remotes, remoteObj)
		output = out(output, "ledgers", remotes, nil, true)
	}
	return output, nil
}

// ExecListLedgers lists the ledgers.
func (m *ConfigManager) ExecListLedgers(output map[string]any, out common.PrinterOutFunc) (map[string]any, error) {
	if output == nil {
		output = map[string]any{}
	}
	cfg, err := m.readConfig()
	if err != nil {
		return output, err
	}
	if m.ctx.IsTerminalOutput() {
		ledgers := []string{}
		for cfgLedger := range cfg.Ledgers {
			cfgLedgerTxt := cfgLedger
			isHead := cfg.Ledgers[cfgLedger].IsHead
			if isHead {
				cfgLedgerTxt = fmt.Sprintf("*%s", cfgLedger)
			}
			ledgers = append(ledgers, cfgLedgerTxt)
		}
		if len(ledgers) == 0 {
			out(nil, "", "Your workspace doesn't have any ledger configured.", nil, true)
		} else {
			out(nil, "", "Your workspace configured ledgers:\n", nil, true)
			for _, ledger := range ledgers {
				out(nil, "", fmt.Sprintf("	- %s", common.KeywordText(ledger)), nil, true)
			}
			out(nil, "", "\n", nil, false)
		}
	} else if m.ctx.IsJSONOutput() {
		ledgers := []any{}
		for cfgLedger := range cfg.Ledgers {
			isHead := cfg.Ledgers[cfgLedger].IsHead
			ledgerObj := map[string]any{
				"ref":        cfg.Ledgers[cfgLedger].Ref,
				"ledger_uri": cfgLedger,
				"ledger_id":  cfg.Ledgers[cfgLedger].LedgerID,
				"is_head":    isHead,
			}
			ledgers = append(ledgers, ledgerObj)
		}
		output = out(output, "ledgers", ledgers, nil, true)
	}
	return output, nil
}
