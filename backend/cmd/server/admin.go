package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"tunnelslate/internal/store"
)

func runAdminCommand(ctx context.Context, databasePath string, args []string, output io.Writer) error {
	if len(args) != 2 || (args[0] != "create-admin" && args[0] != "reset-password" && args[0] != "reset-totp") {
		return fmt.Errorf("usage: create-admin <username> | reset-password <username> | reset-totp <username>")
	}
	if _, err := store.NormalizeAdminUsername(args[1]); err != nil {
		return err
	}
	// Recovery must not silently create an empty database at the wrong path.
	info, err := os.Stat(databasePath)
	if err != nil {
		return fmt.Errorf("open existing application database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("application database must be a regular file")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	db, err := store.Open(ctx, databasePath)
	if err != nil {
		return fmt.Errorf("open application database: %w", err)
	}
	defer db.DB.Close()
	if args[0] == "reset-totp" {
		name, err := db.ResetAdminTOTP(ctx, args[1])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(output, "TOTP disabled for administrator: %s\nAll sessions for this account have ended. Sign in with the existing password and set up TOTP again.\n", name)
		return err
	}
	credentials, err := db.RecoverAdmin(ctx, args[1], args[0] == "create-admin")
	if err != nil {
		return err
	}
	message := "Password reset for administrator"
	if args[0] == "create-admin" {
		message = "Administrator created"
	}
	_, err = fmt.Fprintf(output, "%s: %s\nOne-time password: %s\nSign in and set a permanent password before using the panel.\n", message, credentials.Username, credentials.TemporaryPassword)
	return err
}
