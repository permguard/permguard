package cli

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	azicliaccounts "github.com/permguard/permguard/internal/cli/accounts"
	azicliauthn "github.com/permguard/permguard/internal/cli/authn"
	azicliauthz "github.com/permguard/permguard/internal/cli/authz"
	azicliconfigs "github.com/permguard/permguard/internal/cli/configs"
	azcli "github.com/permguard/permguard/pkg/cli"
	azclicommon "github.com/permguard/permguard/internal/cli/common"
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
		Name:  "Community Command Line Interface",
		Use:   "PermGuard Command Line Interface",
		Short: "The official PermGuard© Cli",
		Long:  azclicommon.BuildCliLongTemplate("PermGuard is an Open Source Multi-Account and Multi-Tenant Authorization Provider."),
	}
}

// GetCliCommands returns commands.
func (s *CommunityCliInitializer) GetCliCommands(deps azcli.CliDependenciesProvider, v *viper.Viper) ([]*cobra.Command, error) {
	accountsCmd := azicliaccounts.CreateCommandForAccounts(deps, v)
	authnCmd := azicliauthn.CreateCommandForAuthN(deps, v)
	authzCmd := azicliauthz.CreateCommandForAuthZ(deps, v)
	configCmd := azicliconfigs.CreateCommandForConfig(deps, v)
	return []*cobra.Command{
		accountsCmd,
		authnCmd,
		authzCmd,
		configCmd,
	}, nil
}
