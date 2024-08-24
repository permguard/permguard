package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azcli "github.com/permguard/permguard/pkg/cli"
)

// CommunityCliInitializer  is the community cli initializer.
type CommunityCliInitializer struct{}

// NewCommunityCliInitializer returns a new initializer.
func NewCommunityCliInitializer() (*CommunityCliInitializer, error) {
	return &CommunityCliInitializer{}, nil
}

// GetCliInfo returns the infos of the cli.
func (s *CommunityCliInitializer) GetCliInfo() azcli.CliInfo {
	return azcli.CliInfo{
		Name:  "Community CLI",
		Use:   "PermGuard CLI",
		Short: "The official PermGuard© CLI",
		Long: `The official PermGuard© CLI
Copyright (c) 2022 Nitro Agility S.r.l.

  Find more information at: https://www.permguard.com/docs/cli/how-to-use/`,
	}
}

// GetCliCommands returns commands.
func (s *CommunityCliInitializer) GetCliCommands(v *viper.Viper) ([]*cobra.Command, error) {
	accountsCmd := createCommandForAccounts(v)
	authnCmd := createCommandForAuthN(v)
	authzCmd := createCommandForAuthZ(v)
	configCmd := createCommandForConfig(v)
	return []*cobra.Command{
		accountsCmd,
		authnCmd,
		authzCmd,
		configCmd,
	}, nil
}
