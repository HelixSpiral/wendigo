package main

import (
	"log/slog"
	"net/http"
	"os"

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

	http.HandleFunc("/token", srv.TokenHandler)

	http.ListenAndServe(":8090", nil)
}
