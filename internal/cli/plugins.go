package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/supunhg/filo-go/internal/plugins"
)

var pluginsCmd = &cobra.Command{
	Use:   "plugins",
	Short: "Manage filo-go plugins",
	Long:  `List, load, and manage filo-go analysis plugins.`,
}

var pluginsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	RunE:  runPluginsList,
}

var pluginsLoadCmd = &cobra.Command{
	Use:   "load [path]",
	Short: "Load a plugin from a .so file",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsLoad,
}

var pluginsInfoCmd = &cobra.Command{
	Use:   "info [name]",
	Short: "Show plugin details",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsInfo,
}

var pluginsInstallCmd = &cobra.Command{
	Use:   "install [path]",
	Short: "Install a plugin from a .so file (alias for load)",
	Args:  cobra.ExactArgs(1),
	RunE:  runPluginsLoad,
}

func init() {
	pluginsCmd.AddCommand(pluginsListCmd)
	pluginsCmd.AddCommand(pluginsLoadCmd)
	pluginsCmd.AddCommand(pluginsInstallCmd)
	pluginsCmd.AddCommand(pluginsInfoCmd)
	rootCmd.AddCommand(pluginsCmd)
}

func runPluginsList(cmd *cobra.Command, args []string) error {
	pluginList := plugins.List()

	if len(pluginList) == 0 {
		fmt.Println()
		fmt.Println("  No plugins installed.")
		fmt.Println()
		fmt.Println("  Install plugins by:")
		fmt.Println("    1. Copy .so files to ~/.filo/plugins/")
		fmt.Println("    2. Use: filo plugins load <path>")
		fmt.Println()
		return nil
	}

	fmt.Printf("\n  Installed Plugins (%d)\n\n", len(pluginList))

	for _, name := range pluginList {
		p, _ := plugins.Get(name)
		fmt.Printf("  %-20s %s\n", p.Name, p.Version)
		if p.Description != "" {
			fmt.Printf("  %-20s %s\n", "", truncate(p.Description, 50))
		}
		if p.Author != "" {
			fmt.Printf("  %-20s by %s\n", "", p.Author)
		}
		fmt.Println()
	}

	return nil
}

func runPluginsLoad(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Check file exists
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("plugin not found: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a plugin file")
	}

	// Try to load
	p, err := plugins.Load(path)
	if err != nil {
		return fmt.Errorf("failed to load plugin: %w", err)
	}

	fmt.Printf("\n  Plugin loaded successfully!\n\n")
	fmt.Printf("  Name:        %s\n", p.Name)
	fmt.Printf("  Version:     %s\n", p.Version)
	fmt.Printf("  Description: %s\n\n", p.Description)

	return nil
}

func runPluginsInfo(cmd *cobra.Command, args []string) error {
	name := args[0]

	p, ok := plugins.Get(name)
	if !ok {
		return fmt.Errorf("plugin %q not found", name)
	}

	fmt.Printf("\n  Plugin: %s\n\n", p.Name)
	fmt.Printf("  Version:     %s\n", p.Version)
	fmt.Printf("  Description: %s\n", p.Description)
	if p.Author != "" {
		fmt.Printf("  Author:      %s\n", p.Author)
	}
	if p.URL != "" {
		fmt.Printf("  URL:         %s\n", p.URL)
	}

	// Show capabilities
	fmt.Printf("\n  Capabilities:\n")
	if p.Analyzer != nil {
		fmt.Printf("    ✓ Analyzer\n")
	}
	if p.Formatter != nil {
		fmt.Printf("    ✓ Formatter\n")
	}
	if p.Transformer != nil {
		fmt.Printf("    ✓ Transformer\n")
	}
	if p.Validator != nil {
		fmt.Printf("    ✓ Validator\n")
	}
	fmt.Println()

	return nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
