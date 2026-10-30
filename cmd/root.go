// Package cmd is skope's command line: `serve` runs the server, everything
// else manages one over its admin API.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rubysolo/skope/internal/client"
)

// Set by the release build.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

var rootCmd = &cobra.Command{
	Use:           "skope",
	Short:         "Watch your projects' dependencies for published vulnerabilities",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "skope:", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(serveCmd, projectCmd, tokenCmd, findingCmd, syncCmd, versionCmd)
}

// adminClient is the client for every management command.
func adminClient() (*client.Client, error) { return client.FromEnv() }

// info writes operator-facing chatter to stderr, keeping stdout for output
// meant to be piped (a token, a table).
func info(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("skope %s %s %s\n", Version, Commit, Date)
	},
}

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Start an advisory sync on the server now",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		if err := c.Sync(); err != nil {
			return err
		}
		info("sync started; findings it opens are alerted as usual")
		return nil
	},
}
