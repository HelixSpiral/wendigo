package server

import (
	"log/slog"
	"os"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/helixspiral/wendigo/internal/config"
	"github.com/helixspiral/wendigo/internal/jwks"
)

type Server struct {
	issuer      string
	providers   []Provider
	signingKeys []SigningKey
	jwks        []map[string]string
}

type Provider struct {
	Name    string `yaml:"Name"`
	Issuer  string `yaml:"Issuer"`
	Keyfunc jwt.Keyfunc
}

type SigningKey struct {
	ID        string `yaml:"ID"`
	Algorithm string `yaml:"Algorithm"`
	Key       string `yaml:"Key"`
}

func New(cfg *config.Config) *Server {
	var providers []Provider
	var signingKeys []SigningKey
	jwksList := []map[string]string{}

	for _, provider := range cfg.Providers {
		jwks, err := keyfunc.NewDefault([]string{provider.KeyFile})
		if err != nil {
			slog.Warn("failed to get jwks for provider", "provider", provider.Name, "error", err)
			continue
		}

		providers = append(providers, Provider{
			Name:    provider.Name,
			Issuer:  provider.Issuer,
			Keyfunc: jwks.Keyfunc,
		})
	}

	for _, key := range cfg.SigningKeys {
		signingKeys = append(signingKeys, SigningKey{
			ID:        key.ID,
			Algorithm: key.Algorithm,
			Key:       key.Key,
		})

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

	return &Server{
		issuer:      cfg.Issuer,
		providers:   providers,
		signingKeys: signingKeys,
		jwks:        jwksList,
	}
}
