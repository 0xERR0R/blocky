// Copyright 2026 Chris Snell
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/0xERR0R/blocky/auth"
	"github.com/0xERR0R/blocky/config"
	"github.com/0xERR0R/blocky/configstore"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// readPassword is exposed as a package-level variable so tests can stub it
// without attaching a real terminal. Default implementation reads from stdin
// with echo suppressed via golang.org/x/term.
//
//nolint:gochecknoglobals
var readPassword = termReadPassword

func termReadPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	pw, err := term.ReadPassword(int(os.Stdin.Fd()))

	fmt.Fprintln(os.Stderr)

	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	return string(pw), nil
}

// openStore opens the configstore using the database path from the loaded
// config file. Each subcommand opens/closes its own store — these are
// short-lived CLI invocations, not long-running processes.
func openStore() (*configstore.ConfigStore, error) {
	cfg, err := config.LoadConfig(configPath, false)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	if cfg.DatabasePath == "" {
		return nil, errors.New("databasePath is not set in config")
	}

	store, err := configstore.Open(cfg.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	return store, nil
}

func newUserCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
	}

	cmd.AddCommand(
		newUserCreateCommand(),
		newUserListCommand(),
		newUserDeleteCommand(),
		newUserResetPasswordCommand(),
	)

	return cmd
}

func newUserCreateCommand() *cobra.Command {
	var username, role string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := auth.ValidateRole(role); err != nil {
				return fmt.Errorf("invalid role: %w", err)
			}

			normalizedUsername := strings.ToLower(strings.TrimSpace(username))
			if err := auth.ValidateUsername(normalizedUsername); err != nil {
				return err
			}

			password, err := readPassword("Password: ")
			if err != nil {
				return err
			}

			if err := auth.ValidatePassword(password); err != nil {
				return err
			}

			confirm, err := readPassword("Confirm password: ")
			if err != nil {
				return err
			}

			if password != confirm {
				return errors.New("passwords do not match")
			}

			hash, err := auth.HashPassword(password)
			if err != nil {
				return err
			}

			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			// Lowercase to honor Phase 1 username-case policy at the CLI layer.
			// CreateUser also normalizes, but making the invariant explicit
			// here avoids surprise if anyone later reads back the struct.
			user := &configstore.User{
				Username:     normalizedUsername,
				PasswordHash: hash,
				Role:         role,
			}

			if err := store.CreateUser(user); err != nil {
				return fmt.Errorf("create user: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Created user %q (id=%d, role=%s)\n", user.Username, user.ID, user.Role)

			return nil
		},
	}

	cmd.Flags().StringVar(&username, "username", "", "username (required)")
	cmd.Flags().StringVar(&role, "role", "", "role: admin or viewer (required)")
	_ = cmd.MarkFlagRequired("username")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

func newUserListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all users",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			users, err := store.ListUsers()
			if err != nil {
				return err
			}

			if len(users) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No users.")

				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tUSERNAME\tROLE\tCREATED AT")

			for _, u := range users {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
					u.ID, u.Username, u.Role, u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"))
			}

			return w.Flush()
		},
	}
}

func newUserDeleteCommand() *cobra.Command {
	var (
		username string
		yes      bool
	)

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			user, err := store.GetUserByUsername(username)
			if err != nil {
				return fmt.Errorf("user %q not found", username)
			}

			if !yes {
				ok, err := confirm(cmd.InOrStdin(), cmd.OutOrStdout(),
					fmt.Sprintf("Delete user %q? This will invalidate all their sessions. [y/N]: ", user.Username))
				if err != nil {
					return err
				}

				if !ok {
					fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")

					return nil
				}
			}

			// DeleteUser refuses to remove the last admin (returns an error)
			// and calls DeleteSessionsForUser internally per Phase 1 handoff.
			if err := store.DeleteUser(user.ID); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Deleted user %q.\n", user.Username)

			return nil
		},
	}

	cmd.Flags().StringVar(&username, "username", "", "username to delete (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip confirmation prompt")
	_ = cmd.MarkFlagRequired("username")

	return cmd
}

func newUserResetPasswordCommand() *cobra.Command {
	var username string

	cmd := &cobra.Command{
		Use:   "reset-password",
		Short: "Reset a user's password",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStore()
			if err != nil {
				return err
			}
			defer store.Close()

			user, err := store.GetUserByUsername(username)
			if err != nil {
				return fmt.Errorf("user %q not found", username)
			}

			password, err := readPassword("New password: ")
			if err != nil {
				return err
			}

			if err := auth.ValidatePassword(password); err != nil {
				return err
			}

			confirmPw, err := readPassword("Confirm new password: ")
			if err != nil {
				return err
			}

			if password != confirmPw {
				return errors.New("passwords do not match")
			}

			hash, err := auth.HashPassword(password)
			if err != nil {
				return err
			}

			// ResetPassword updates the hash AND invalidates all sessions
			// for the user, honoring the "no stale session survives a
			// credential change" invariant (Phase 1 handoff lines 174-179).
			if err := store.ResetPassword(user.ID, hash); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Password reset for user %q; existing sessions invalidated.\n", user.Username)

			return nil
		},
	}

	cmd.Flags().StringVar(&username, "username", "", "username (required)")
	_ = cmd.MarkFlagRequired("username")

	return cmd
}

// confirm reads a line of input and returns true for yes/y (case-insensitive),
// false for anything else. An empty line is treated as the default: no.
func confirm(in io.Reader, out io.Writer, prompt string) (bool, error) {
	fmt.Fprint(out, prompt)

	r := bufio.NewReader(in)

	line, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, fmt.Errorf("read confirmation: %w", err)
	}

	answer := strings.ToLower(strings.TrimSpace(line))

	return answer == "y" || answer == "yes", nil
}
