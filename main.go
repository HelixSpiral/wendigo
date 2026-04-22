package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/helixspiral/wendigo/internal/config"
	"github.com/helixspiral/wendigo/internal/server"
	"gopkg.in/yaml.v3"
)

func main() {
	cfgFile, err := os.ReadFile("config.yml")
	if err != nil {
		slog.Error("failed to read config file", "error", err)

		os.Exit(1)
	}

	slog.Info("config file loaded", "path", "config.yml")

	var cfg config.Config

	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		slog.Error("failed to parse config file", "error", err)

		os.Exit(1)
	}

	slog.Info("config parsed successfully")

	srv := server.New(&cfg)

	slog.Info("server created successfully")

	http.HandleFunc("/.well-known/jwks.json", srv.JwksHandler)

	httpSrv := &http.Server{
		Addr: ":8090",
	}

	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM, os.Interrupt)

	go func() {
		sig := <-sigTerm
		slog.Info("signal received", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := httpSrv.Shutdown(ctx); err != nil {
			slog.Error("error gracefully shutting down, forcing exit", "error", err)

			os.Exit(1)
		}
	}()

	http.HandleFunc("/token", srv.TokenHandler)

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("error in listening", "error", err)

		os.Exit(1)
	}

	slog.Info("shutdown complete")
}
