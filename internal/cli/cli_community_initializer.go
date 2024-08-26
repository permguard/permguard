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
		Name:  "Community Cli",
		Use:   "PermGuard Cli",
		Short: "The official PermGuard© Cli",
		Long:  cliLongTemplate,
	}
}

// GetCliCommands returns commands.
func (s *CommunityCliInitializer) GetCliCommands(deps azcli.CliDependenciesProvider, v *viper.Viper) ([]*cobra.Command, error) {
	accountsCmd := createCommandForAccounts(deps, v)
	authnCmd := createCommandForAuthN(deps, v)
	authzCmd := createCommandForAuthZ(deps, v)
	configCmd := createCommandForConfig(deps, v)
	return []*cobra.Command{
		accountsCmd,
		authnCmd,
		authzCmd,
		configCmd,
	}, nil
}
