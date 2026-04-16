package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/helixspiral/wendigo/internal/config"
	"github.com/helixspiral/wendigo/internal/jwks"
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

	jwksList := []map[string]string{}

	for _, key := range cfg.SigningKeys {
		jwk, err := jwks.FromSigningKey(key)
		if err != nil {
			slog.Error("failed to get jwk", "error", err)

			os.Exit(1)
		}

		if jwk == nil {
			continue
		}

		jwksList = append(jwksList, jwk)
	}

	fmt.Println(jwksList)

	http.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"keys": jwksList,
		})
	})

	http.HandleFunc("/token", srv.TokenHandler)

	http.ListenAndServe(":8090", nil)
}
