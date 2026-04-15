package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

func main() {
	cfgFile, err := os.ReadFile("config.yml")
	if err != nil {
		slog.Error("failed to read config file", "err", err)

		os.Exit(1)
	}

	slog.Info("config file loaded", "path", "config.yml")

	var cfg Config

	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		slog.Error("failed to parse config file", "err", err)

		os.Exit(1)
	}

	slog.Info("config parsed successfully")

	jwksList := []map[string]string{}

	for _, key := range cfg.SigningKeys {
		jwk, err := key.returnJWK()
		if err != nil {
			slog.Error("failed to get jwk", "err", err)

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

	http.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		authHeader, ok := req.Header["Authorization"]
		if !ok {
			slog.Warn("Request missing authorization header", "path", req.URL.Path)
			http.Error(w, "No auth header", http.StatusUnauthorized)
			return
		}

		if len(authHeader) < 1 {
			slog.Warn("Authorization header is empty", "path", req.URL.Path)
			http.Error(w, "Auth header invalid", http.StatusUnauthorized)
			return
		}

		slog.Info("authorization header received", "path", req.URL.Path)

		headerSplit := strings.Split(authHeader[0], " ")
		if len(headerSplit) < 2 {
			slog.Warn("Authorization header format invalid", "path", req.URL.Path)
			http.Error(w, "Auth header invalid", http.StatusUnauthorized)
			return
		}

		rawJwt := headerSplit[1]

		for _, provider := range cfg.Providers {
			jwks, err := keyfunc.NewDefault([]string{provider.KeyFile})
			if err != nil {
				slog.Warn("failed to get jwks for provider", "provider", provider.Name, "err", err)
				continue
			}

			provider.Keyfunc = jwks.Keyfunc

			token, err := provider.verifyToken(rawJwt)
			if err != nil {
				slog.Warn("failed to verify token with provider", "provider", provider.Name, "err", err)
				continue
			}

			slog.Info("token verified successfully", "provider", provider.Name)

			newToken := jwt.NewWithClaims(jwt.GetSigningMethod(cfg.SigningKeys[0].Algorithm), token.Claims)
			newToken.Claims.(jwt.MapClaims)["iss"] = cfg.Issuer
			newToken.Header["kid"] = cfg.SigningKeys[0].ID

			slog.Info("new token created", "provider", provider.Name, "algorithm", cfg.SigningKeys[0].Algorithm)

			var signedToken string

			switch cfg.SigningKeys[0].Algorithm {
			case "HS256", "HS284", "HS512":
				signedToken, err = newToken.SignedString([]byte(cfg.SigningKeys[0].Key))
			case "RS256", "RS384", "RS512":
				keyFile, err := os.ReadFile(cfg.SigningKeys[0].Key)
				if err != nil {
					slog.Error("failed to read signing key file", "path", cfg.SigningKeys[0].Key, "err", err)
					http.Error(w, "error reading key file", http.StatusInternalServerError)

					return
				}
				key, err := jwt.ParseRSAPrivateKeyFromPEM(keyFile)
				if err != nil {
					slog.Error("failed to parse RSA private key", "err", err)
					http.Error(w, "error parsing key", http.StatusInternalServerError)

					return
				}
				signedToken, err = newToken.SignedString(key)
			}

			if err != nil {
				slog.Error("failed to sign token", "algorithm", cfg.SigningKeys[0].Algorithm, "err", err)
				http.Error(w, "error signing token", http.StatusInternalServerError)

				return
			}

			slog.Info("token signed and returned successfully", "provider", provider.Name)

			fmt.Fprintln(w, signedToken)

			return
		}

		// If we reach here, no provider could verify the token.
		slog.Warn("no provider could verify the token", "path", req.URL.Path)

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})

	http.ListenAndServe(":8090", nil)
}
