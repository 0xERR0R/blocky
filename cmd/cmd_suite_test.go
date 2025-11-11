package cmd

import (
	"context"
	"testing"

	"github.com/0xERR0R/blocky/log"
	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func init() {
	log.Silence()
}

func TestCmd(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Command Suite")
}

// withContext wraps a cobra.Command and sets a context on it for testing
func withContext(cmd *cobra.Command) *cobra.Command {
	ctx := context.Background()
	cmd.SetContext(ctx)

	return cmd
}
