package server

import (
	"log/slog"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/helixspiral/wendigo/internal/config"
)

type Server struct {
	issuer      string
	providers   []Provider
	signingKeys []SigningKey
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

type NewServerInputConfig struct {
	Issuer      string
	Providers   []Provider
	SigningKeys []SigningKey
}

func New(cfg *config.Config) *Server {
	var providers []Provider
	var signingKeys []SigningKey

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
	}

	return &Server{
		issuer:      cfg.Issuer,
		providers:   providers,
		signingKeys: signingKeys,
	}
}
