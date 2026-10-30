package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

var projectCmd = &cobra.Command{Use: "project", Short: "Manage projects"}

var projectAddCmd = &cobra.Command{
	Use:   "add NAME",
	Short: "Register a project and print its token",
	Long: `Register a project and print its project token on stdout — and only there,
so it can be piped straight into a CI secret:

  skope project add my-app | gh secret set SKOPE_TOKEN --repo me/my-app`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		pt, err := c.CreateProject(args[0])
		if err != nil {
			return err
		}
		fmt.Println(pt.Token)
		info("registered %s; the token above is shown only once", pt.Project.Name)
		return nil
	},
}

var projectListCmd = &cobra.Command{
	Use:   "list",
	Short: "List projects",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		ps, err := c.Projects()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tLAST REPORT\tSTATUS")
		for _, p := range ps {
			status, last := "active", p.LastReportAt
			if p.ArchivedAt != "" {
				status = "archived"
			}
			if last == "" {
				last = "never"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", p.Name, last, status)
		}
		return w.Flush()
	},
}

var projectArchiveCmd = &cobra.Command{
	Use:   "archive NAME",
	Short: "Retire a project: revoke its token and stop watching it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		if err := c.ArchiveProject(args[0]); err != nil {
			return err
		}
		info("archived %s", args[0])
		return nil
	},
}

var deleteYes bool

var projectDeleteCmd = &cobra.Command{
	Use:   "delete NAME",
	Short: "Erase a project and everything recorded about it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !deleteYes {
			return errors.New("deleting erases the project's findings and history; pass --yes to confirm (or use `archive`)")
		}
		c, err := adminClient()
		if err != nil {
			return err
		}
		if err := c.DeleteProject(args[0]); err != nil {
			return err
		}
		info("deleted %s", args[0])
		return nil
	},
}

var tokenCmd = &cobra.Command{Use: "token", Short: "Manage project tokens"}

var tokenRotateCmd = &cobra.Command{
	Use:   "rotate PROJECT",
	Short: "Replace a project's token and print the new one",
	Long: `Replace a project's token; the old one stops working immediately. The new
token is printed on stdout only:

  skope token rotate my-app | gh secret set SKOPE_TOKEN --repo me/my-app`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		pt, err := c.RotateToken(args[0])
		if err != nil {
			return err
		}
		fmt.Println(pt.Token)
		info("rotated the token for %s", args[0])
		return nil
	},
}

var findingCmd = &cobra.Command{Use: "finding", Short: "Review and mute findings"}

var (
	findingProject string
	findingAll     bool
	ignoreReason   string
	ignoreUntil    string
)

var findingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List open findings, most severe first",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := adminClient()
		if err != nil {
			return err
		}
		fs, err := c.Findings(findingProject, findingAll)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSEVERITY\tPROJECT\tPACKAGE\tVERSIONS\tADVISORY\tSTATUS")
		for _, f := range fs {
			status := "open"
			switch {
			case f.ResolvedAt != "":
				status = "resolved"
			case f.Ignored != nil:
				status = "ignored: " + f.Ignored.Reason
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s/%s\t%s\t%s\t%s\n", f.ID, f.Severity, f.Project, f.Ecosystem, f.Package, f.Versions, f.Advisory, status)
		}
		return w.Flush()
	},
}

var findingIgnoreCmd = &cobra.Command{
	Use:   "ignore ID",
	Short: "Mute a finding; it comes back if its advisory changes or --until passes",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("finding id must be a number: %q", args[0])
		}
		c, err := adminClient()
		if err != nil {
			return err
		}
		if err := c.Ignore(id, ignoreReason, ignoreUntil); err != nil {
			return err
		}
		info("ignored finding %d", id)
		return nil
	},
}

var findingUnignoreCmd = &cobra.Command{
	Use:   "unignore ID",
	Short: "Unmute a finding",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("finding id must be a number: %q", args[0])
		}
		c, err := adminClient()
		if err != nil {
			return err
		}
		if err := c.Unignore(id); err != nil {
			return err
		}
		info("finding %d is active again", id)
		return nil
	},
}

func init() {
	projectDeleteCmd.Flags().BoolVar(&deleteYes, "yes", false, "confirm the deletion")
	projectCmd.AddCommand(projectAddCmd, projectListCmd, projectArchiveCmd, projectDeleteCmd)
	tokenCmd.AddCommand(tokenRotateCmd)

	findingListCmd.Flags().StringVar(&findingProject, "project", "", "only this project")
	findingListCmd.Flags().BoolVar(&findingAll, "all", false, "include resolved findings")
	findingIgnoreCmd.Flags().StringVar(&ignoreReason, "reason", "", "why this finding doesn't apply (required)")
	findingIgnoreCmd.Flags().StringVar(&ignoreUntil, "until", "", "unmute automatically on this date (2027-01-01)")
	findingIgnoreCmd.MarkFlagRequired("reason")
	findingCmd.AddCommand(findingListCmd, findingIgnoreCmd, findingUnignoreCmd)
}
