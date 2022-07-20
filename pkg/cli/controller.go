package cli

import (
	cli "github.com/acorn-io/acorn/pkg/cli/builder"
	"github.com/acorn-io/acorn/pkg/controller"
	"github.com/spf13/cobra"
)

func NewController() *cobra.Command {
	return cli.Command(&Controller{}, cobra.Command{
		Use:          "controller",
		SilenceUsage: true,
		Hidden:       true,
		Short:        "Run k8s controller",
		Args:         cobra.NoArgs,
	})
}

type Controller struct {
}

func (s *Controller) Run(cmd *cobra.Command, args []string) error {
	c, err := controller.New(cmd.Context())
	if err != nil {
		return err
	}
	if err := c.Start(cmd.Context()); err != nil {
		return err
	}
	<-cmd.Context().Done()
	return nil
}
