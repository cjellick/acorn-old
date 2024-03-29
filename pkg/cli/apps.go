package cli

import (
	cli "github.com/acorn-io/acorn/pkg/cli/builder"
	"github.com/acorn-io/acorn/pkg/cli/builder/table"
	"github.com/acorn-io/acorn/pkg/client"
	"github.com/acorn-io/acorn/pkg/system"
	"github.com/acorn-io/acorn/pkg/tables"
	"github.com/spf13/cobra"
	"k8s.io/utils/strings/slices"
)

func NewApp() *cobra.Command {
	return cli.Command(&App{}, cobra.Command{
		Use:     "app [flags] [APP_NAME...]",
		Aliases: []string{"apps", "a", "ps"},
		Example: `
acorn app`,
		SilenceUsage: true,
		Short:        "List or get apps",
	})
}

type App struct {
	All    bool   `usage:"Include stopped apps" short:"a"`
	Quiet  bool   `usage:"Output only names" short:"q"`
	Output string `usage:"Output format (json, yaml, {{gotemplate}})" short:"o"`
}

func (a *App) Run(cmd *cobra.Command, args []string) error {
	client, err := client.Default()
	if err != nil {
		return err
	}

	out := table.NewWriter(tables.App, system.UserNamespace(), a.Quiet, a.Output)

	if len(args) == 1 {
		app, err := client.AppGet(cmd.Context(), args[0])
		if err != nil {
			return err
		}
		out.Write(app)
		return out.Err()
	}

	apps, err := client.AppList(cmd.Context())
	if err != nil {
		return err
	}

	for _, app := range apps {
		if app.Status.Stopped && !a.All {
			continue
		}
		if len(args) > 0 {
			if slices.Contains(args, app.Name) {
				out.Write(app)
			}
		} else {
			out.Write(app)
		}
	}

	return out.Err()
}
