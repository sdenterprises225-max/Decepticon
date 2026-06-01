package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/compose"
	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/config"
	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/sandbox"
	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/ui"
	"github.com/spf13/cobra"
)

var sandboxCmd = &cobra.Command{
	Use:   "sandbox",
	Short: "Manage per-engagement sandbox containers",
}

var sandboxStartCmd = &cobra.Command{
	Use:   "start <engagement>",
	Short: "Start or replace the sandbox for one engagement",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		env, err := config.LoadEnv(config.EnvPath())
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		home := config.DecepticonHome()
		slug := args[0]
		workspace := filepath.Join(home, "workspace", slug)
		mgr := sandbox.NewManager(compose.New(), env)
		creds, url, err := mgr.Ensure(slug, workspace)
		if err != nil {
			return err
		}
		ui.Success("Sandbox ready: " + sandbox.ContainerName(slug))
		ui.DimText("LangGraph sandbox URL: " + url)
		ui.DimText("Cypher user: " + creds.Username + " (" + creds.Path + ")")
		return nil
	},
}

var sandboxStopCmd = &cobra.Command{
	Use:   "stop <engagement>",
	Short: "Stop and remove the sandbox for one engagement",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := sandbox.NewManager(compose.New(), nil).Stop(args[0]); err != nil {
			return err
		}
		ui.Success("Sandbox removed: " + sandbox.ContainerName(args[0]))
		return nil
	},
}

var sandboxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List running per-engagement sandboxes",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return sandbox.NewManager(compose.New(), nil).List()
	},
}

func init() {
	sandboxCmd.AddCommand(sandboxStartCmd, sandboxStopCmd, sandboxListCmd)
	rootCmd.AddCommand(sandboxCmd)
}
