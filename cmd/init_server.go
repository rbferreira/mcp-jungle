package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/mcpjungle/mcpjungle/cmd/config"
	"github.com/spf13/cobra"
)

var initServerBootstrapToken string

var initServerCmd = &cobra.Command{
	Use:   "init-server",
	Short: "Initialize the MCPJungle Server (for Enterprise Mode only)",
	Long: "If the MCPJungle Server was started in Enterprise Mode, use this command to initialize the server.\n" +
		"Initialization is required before you can use the server.\n",
	RunE: runInitServer,
	Annotations: map[string]string{
		"group": string(subCommandGroupAdvanced),
		"order": "6",
	},
}

func init() {
	initServerCmd.Flags().StringVar(&initServerBootstrapToken, "bootstrap-token", "", "one-time enterprise bootstrap token (or MCPJUNGLE_BOOTSTRAP_TOKEN)")
	rootCmd.AddCommand(initServerCmd)
}

func runInitServer(cmd *cobra.Command, args []string) error {
	fmt.Println("Initializing the MCPJungle Server in Enterprise Mode...")
	bootstrapToken := initServerBootstrapToken
	if bootstrapToken == "" {
		bootstrapToken = os.Getenv("MCPJUNGLE_BOOTSTRAP_TOKEN")
	}
	if bootstrapToken == "" {
		return errors.New("bootstrap token is required; use --bootstrap-token or MCPJUNGLE_BOOTSTRAP_TOKEN")
	}
	resp, err := apiClient.InitServerWithBootstrapToken(bootstrapToken)
	if err != nil {
		return fmt.Errorf("failed to initialize the server: %w", err)
	}

	if resp.AdminAccessToken == "" {
		return errors.New("server initialization failed: no admin access token received")
	}

	// Create new client configuration
	cfg := &config.ClientConfig{
		RegistryURL: apiClient.BaseURL(),
		AccessToken: resp.AdminAccessToken,
	}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("failed to create client configuration: %w", err)
	}

	cfgPath, err := config.AbsPath()
	if err != nil {
		return fmt.Errorf("failed to get client configuration path: %w", err)
	}
	fmt.Println("Your Admin access token has been saved to", cfgPath)

	fmt.Println("All done!")
	return nil
}
