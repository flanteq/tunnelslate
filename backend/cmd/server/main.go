package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"tunnelslate/internal/branding"

	"tunnelslate/internal/buildinfo"
	"tunnelslate/internal/config"
	"tunnelslate/internal/server"
	"tunnelslate/internal/store"
)

func main() {
	syscall.Umask(0077)
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(branding.Name + " " + buildinfo.Version)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		client := http.Client{Timeout: 3 * time.Second}
		r, err := client.Get("http://127.0.0.1:8080/healthz")
		if err != nil {
			os.Exit(1)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 {
		if err := runAdminCommand(context.Background(), config.DatabasePath, os.Args[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	// Restrict newly created DB/WAL/SHM and future PKI files, including on bind mounts.
	syscall.Umask(0077)
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.DB.Close()
	if err := db.Bootstrap(ctx); err != nil {
		return err
	}
	handler, err := server.New(cfg, db)
	if err != nil {
		return err
	}
	if err := handler.StartVPNAuth(ctx); err != nil {
		return fmt.Errorf("start VPN authentication: %w", err)
	}
	go handler.Run(ctx)
	srv := &http.Server{Addr: cfg.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 360 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errors := make(chan error, 1)
	go func() { errors <- srv.ListenAndServe() }()
	slog.Info("tunnelslate listening", "address", cfg.Listen, "vpn_integration", "management_socket")
	select {
	case err := <-errors:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		handler.StopEvents()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
